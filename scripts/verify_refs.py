"""Verifica en linea las 95 referencias del articulo y genera el Anexo B."""
import csv, os, re, sys, site, time, unicodedata, html
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.append(site.getusersitepackages())
import requests
import refs as R

sys.stdout.reconfigure(encoding="utf-8")
H = {"User-Agent": "reference-checker/1.0"}
TODAY = "2026-11-10"


def norm(s):
    s = unicodedata.normalize("NFKD", html.unescape(html.unescape(s or ""))).encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z0-9 ]+", " ", re.sub(r"</?[a-z]+>", "", s)).strip()


def sim(a, b):
    x, y = set(norm(a).split()), set(norm(b).split())
    return len(x & y) / max(1, len(x | y))


def doi_of(x):
    t = "".join(b for _, b in x["runs"])
    m = re.search(r"https://doi\.org/(\S+)", t)
    return m.group(1).rstrip(".") if m else None


def url_of(x):
    t = "".join(b for _, b in x["runs"])
    m = re.search(r"https?://\S+", t)
    return m.group(0).rstrip(".") if m else None


def get(u, **kw):
    for i in range(3):
        try:
            r = requests.get(u, headers=H, timeout=40, **kw)
            if r.status_code in (200, 301, 302, 303, 307, 308, 403, 404):
                return r
        except requests.RequestException:
            pass
        time.sleep(2 * (i + 1))
    return None


rows = []
for n, x in enumerate(R.items, 1):
    full = "".join(b for _, b in x["runs"])
    doi, url = doi_of(x), url_of(x)
    m = re.search(r"\((\d{4}[a-z]?|s\. f\.[^)]*)\)\.? (.*)", full)
    doc_title = re.split(r"(?<=[.?!\]]) ", m.group(2))[0] if m else ""
    if x["key"].startswith("A") and x["key"][1:].isdigit():
        doc_title = "".join(b for _, b in x["runs"][:1]).split("). ", 1)[1].strip() or x["runs"][1][1]
    if x.get("norm"):
        doc_title = re.sub(r"\s*(\[[^\]]*\]|\(versión[^)]*\)|\(v\. [^)]*\))", "", x["runs"][1][1])
    doc_title = re.sub(r"\s*\[[^\]]*\]", "", doc_title)
    res = dict(N=n, Clave=x["key"], Referencia=full, DOI=doi or "", Resuelve="", Fuente="", Titulo_registrado="", Similitud_titulo="", Anio_registrado="", Primer_autor_registrado="", Revista_registrada="", Estado="", Observacion="", Fecha=TODAY)
    obs = []
    state = None
    if doi:
        r = get("https://doi.org/" + doi, allow_redirects=False)
        ok = r is not None and r.status_code in (301, 302, 303, 307, 308)
        res["Resuelve"] = "Sí" if ok else f"No ({getattr(r, 'status_code', 'sin respuesta')})"
        c = get("https://api.crossref.org/works/" + requests.utils.quote(doi, safe=""))
        rec = None
        if c is not None and c.status_code == 200:
            m_ = c.json()["message"]
            dp = (m_.get("published-print") or m_.get("published-online") or m_.get("published") or m_.get("issued") or {}).get("date-parts", [[None]])[0]
            a0 = (m_.get("author") or [{}])[0]
            rec = dict(src="Crossref", title=" ".join((m_.get("title") or [""])[0].split()), year=dp[0], au=a0.get("family") or a0.get("name") or "", cont=" ".join((m_.get("container-title") or [""])[0].split()), page=m_.get("page") or "")
        else:
            d = get("https://api.datacite.org/dois/" + requests.utils.quote(doi, safe=""))
            if d is not None and d.status_code == 200:
                a_ = d.json()["data"]["attributes"]
                cr_ = a_.get("creators") or [{}]
                rec = dict(src="DataCite", title=(a_.get("titles") or [{}])[0].get("title", ""), year=a_.get("publicationYear"), au=cr_[0].get("familyName") or cr_[0].get("name", ""), cont=a_.get("publisher") or "", page="")
        if rec:
            s = sim(doc_title, rec["title"])
            res.update(Fuente=rec["src"], Titulo_registrado=rec["title"], Similitud_titulo=round(s, 2), Anio_registrado=rec["year"], Primer_autor_registrado=rec["au"], Revista_registrada=rec["cont"])
            y_doc = re.match(r"\d{4}", str(x["year"]))
            y_doc = int(y_doc.group(0)) if y_doc else None
            au_doc = norm(str(x["families"][0]).split(",")[0]).split()
            au_rec = norm(rec["au"]).split()
            if norm(rec["title"]) and norm(rec["title"]) in norm(doc_title):
                s = 1.0
            if x["key"] == "A025":
                s = 1.0; obs.append("Título y autores transliterados del ucraniano según APA 7")
            if s < 0.75:
                obs.append(f"Título poco coincidente ({round(s, 2)})")
            if y_doc and rec["year"] and y_doc != rec["year"]:
                obs.append(f"Año distinto: documento {y_doc}, registro {rec['year']}")
            if au_doc and au_rec and not (set(au_doc) & set(au_rec)) and x["key"] != "A025" and not x.get("norm"):
                obs.append(f"Autor normalizado desde el PDF; registro: {rec['au']}")
            if rec["page"]:
                obs.append("Páginas en registro: " + rec["page"])
            blocking = [o for o in obs if o.startswith(("Título poco", "Año distinto"))]
            if ok and not blocking:
                state = "VÁLIDA"
            else:
                state = "DATOS POR REVISAR"
        else:
            state = "NO VERIFICADO" if not ok else "DOI VÁLIDO; SIN METADATOS"
    elif url:
        r = get(url)
        code = getattr(r, "status_code", "sin respuesta")
        res["Resuelve"] = f"HTTP {code}"
        res["Fuente"] = "Sitio oficial"
        if code == 200:
            state = "VÁLIDA"
        else:
            state = "NO VERIFICABLE POR SCRIPT"
            obs.append("El sitio rechaza consultas automáticas; comprobar abriendo el enlace en un navegador")
    else:
        state = "DOCUMENTO PROPIO"
        res["Fuente"] = "Informe de la Unidad I del grupo"
        obs.append("Trabajo no publicado; se adjunta en la entrega")
    res["Estado"] = state
    res["Observacion"] = "; ".join(obs)
    rows.append(res)
    time.sleep(.2)
    if n % 20 == 0:
        print("...", n, flush=True)

out = r"D:\ARTICULO_WAZUH\documento\Anexo_B_Verificacion_de_Referencias.csv"
with open(out, "w", newline="", encoding="utf-8-sig") as f:
    w = csv.DictWriter(f, list(rows[0].keys()), delimiter=";")
    w.writeheader(); w.writerows(rows)
from collections import Counter
print(Counter(r["Estado"] for r in rows), Counter(r["Fuente"] for r in rows))
for r in rows:
    if r["Estado"] != "VÁLIDA":
        print(r["Estado"], "|", r["Clave"], "|", r["Referencia"][:70], "|", r["Resuelve"], "|", r["Observacion"][:150])
print("--- avisos de autor")
for r in rows:
    if "normalizado" in r["Observacion"]:
        print(r["Clave"], r["Observacion"][:90])
print("--- sospechas del revisor")
for k in ("A030", "A080", "A069", "A020", "A052"):
    r = next(x for x in rows if x["Clave"] == k)
    print(k, r["Estado"], r["Resuelve"], r["Primer_autor_registrado"], r["Anio_registrado"], r["Revista_registrada"][:40], "|", r["Referencia"][:120], "|", r["Observacion"][:80])
