import base64, html, json, os, re, subprocess, sys, site
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.append(site.getusersitepackages())
sys.stdout.reconfigure(encoding="utf-8")
import refs as R
import fitz
from PIL import Image

D = r"D:\ARTICULO_WAZUH\documento"
FIG = r"D:\ARTICULO_WAZUH\figuras"
BASE = "Articulo_Wazuh_Cuatro_Servidores"
TITLE = "Diseño de una solución de monitoreo distribuido con Wazuh en cuatro servidores para la correlación de alertas y la detección de ataques multietapa con aprendizaje automático"
KEYWORDS = "Wazuh, SIEM, correlación de alertas, ataques multietapa, aprendizaje automático, monitoreo distribuido"
AUTH = ["Anampa Pancca, David Jordan", "Vargas Gutiérrez, Ángel José", "Salas Jimenez, Walter Emmanuel", "Huanca Merma, Gregory Brandon"]
txt = open(os.path.join(D, "contenido.txt"), encoding="utf-8").read().splitlines()

CITE = R.CITE
ORDER = {x["key"]: n for n, x in enumerate(R.items)}
used = set()
fig_no, tab_no, first_ref, placed = {}, {}, {}, {}


LONG = {"ISO": "International Organization for Standardization [ISO]", "NIST": "National Institute of Standards and Technology [NIST]"}
_seen_long = set()


def cname(k):
    n = CITE[k][0]
    if n in LONG and n not in _seen_long:
        _seen_long.add(n)
        return LONG[n]
    return n


def cite_tok(m):
    tok = m.group(1)
    if tok.startswith("n:"):
        k = tok[2:]
        assert k in CITE, k
        used.add(k)
        return f"{CITE[k][0]} ({CITE[k][1]})"
    ks = [k.strip() for k in tok.split(",")]
    for k in ks:
        assert k in CITE, f"cita inexistente {k}"
        used.add(k)
    ks = sorted(ks, key=lambda k: ORDER[k])
    return "(" + "; ".join(f"{cname(k)}, {CITE[k][1]}" for k in ks) + ")"


# numeracion en orden de aparicion del objeto
seqf, seqt = 0, 0
for l in txt:
    if l.startswith("@fig "):
        seqf += 1; fig_no[l[5:].split("|")[0]] = seqf
    if l.startswith("@tabla "):
        seqt += 1; tab_no[l[7:].split("|")[0]] = seqt


def xref(m, pos):
    kind, k = m.group(1), m.group(2)
    assert (k in fig_no if kind == "F" else k in tab_no), k
    first_ref.setdefault((kind, k), pos)
    return f"{'Figura' if kind == 'F' else 'Tabla'} {fig_no[k] if kind == 'F' else tab_no[k]}"


def proc(s, pos):
    s = re.sub(r"\{\{([FT]):(\w+)\}\}", lambda m: xref(m, pos), s)
    s = re.sub(r"\{([An]?[:A-Z0-9, ]*[A-Z0-9])\}", cite_tok, s)
    assert "{" not in s, s[:90]
    return s


def runs(s):
    out = []
    for p in re.split(r"(\*\*.+?\*\*|\*.+?\*|`.+?`)", s):
        if not p:
            continue
        if p.startswith("**"):
            out.append({"t": p[2:-2], "b": True})
        elif p.startswith("`"):
            out.append({"t": p[1:-1], "c": True})
        elif p.startswith("*"):
            out.append({"t": p[1:-1], "i": True})
        else:
            out.append({"t": p})
    return out


blocks, i, h1, h2 = [], 0, 0, 0
while i < len(txt):
    l = txt[i].rstrip()
    i += 1
    if not l:
        continue
    pos = len(blocks)
    if l.startswith("# "):
        h1 += 1; h2 = 0
        blocks.append({"k": "h1", "t": f"{h1}. {l[2:].upper()}"})
    elif l.startswith("## "):
        h2 += 1
        blocks.append({"k": "h2", "t": f"{h1}.{h2} {l[3:]}"})
    elif l.startswith("- "):
        blocks.append({"k": "li", "r": runs(proc(l[2:], pos))})
    elif l.startswith("@fig "):
        k, f, ti, note = l[5:].split("|")
        placed[("F", k)] = pos
        im = Image.open(os.path.join(FIG, f))
        blocks.append({"k": "fig", "n": fig_no[k], "file": f, "title": ti, "note": note, "w": im.width, "h": im.height})
    elif l.startswith("@tabla "):
        k, ti = l[7:].split("|", 1)
        placed[("T", k)] = pos
        rows = []
        while txt[i].startswith("|"):
            rows.append([proc(c.strip(), pos) for c in txt[i].strip().strip("|").split("|")])
            i += 1
        note = ""
        if txt[i].startswith("@nota "):
            note = proc(txt[i][6:], pos); i += 1
        n = len(rows[0])
        assert all(len(r) == n for r in rows), ti
        blocks.append({"k": "tab", "n": tab_no[k], "title": ti, "note": note, "rows": [[runs(c) for c in r] for r in rows]})
    else:
        blocks.append({"k": "p", "r": runs(proc(l, pos))})

for key, p in placed.items():
    assert key in first_ref, f"sin mencion {key}"
    assert first_ref[key] <= p, f"mencion despues de aparecer {key}"
refs = []
for x in R.items:
    rr = []
    for a, b in x["runs"]:
        b = b.replace("Ai-enabled", "AI-enabled").replace(", (.", ".").replace(" (.", "")
        b = re.sub(r"wazuh", "Wazuh", b) if not b.startswith("https") else b
        b = re.sub(r"Siem|siem", "SIEM", b) if not b.startswith("https") else b
        for part in re.split(r"(https?://\S+)", b):
            if part:
                rr.append({"t": part, "i": a == "i", "u": part.startswith("http")})
    refs.append(rr)
h1 += 1
ref_head = f"{h1}. REFERENCIAS BIBLIOGRÁFICAS"
missing = [x["key"] for x in R.items if x["key"] not in used]
print("citas distintas", len(used), "referencias", len(R.items), "sin_citar", missing)
assert not missing
articulos = sum(1 for k in used if re.fullmatch(r"A\d{3}", k))
print("articulos citados", articulos)
words = sum(len("".join(r["t"] for r in b.get("r", [])).split()) for b in blocks if b["k"] in ("p", "li"))
print("palabras texto", words, "tablas", seqt, "figuras", seqf)
import csv as _csv
_rows = list(_csv.DictReader(open(r"D:\ARTICULO_WAZUH\documento\Anexo_B_Verificacion_de_Referencias.csv", encoding="utf-8-sig"), delimiter=";"))
ANNEX = []
for r_ in _rows:
    ref = r_["Referencia"]
    aut = ref.split(" (")[0].split(",")[0]
    year = re.search(r"\((\d{4}[a-z]?|s\. f\.[^)]*)\)", ref)
    link = "https://doi.org/" + r_["DOI"] if r_["DOI"] else next(iter(re.findall(r"https?://\S+", ref)), "")
    sim_ = r_["Similitud_titulo"]
    ANNEX.append([r_["N"], f"{aut}, {year.group(1) if year else ''}", link, re.sub(r"</?[a-zA-Z]+>", "", html.unescape(html.unescape(html.unescape(r_["Titulo_registrado"])))).replace("Informe de la Unidad I del grupo", "") or "—", str(r_["Anio_registrado"] or "—"), r_["Fuente"].replace("Informe de la Unidad I del grupo", "Informe propio"), ("No aplica" if not sim_ else "No" if "poco coincidente" in r_["Observacion"] else "Sí"), r_["Resuelve"] or "—", ("Unidad I" if r_["Clave"] in ("SOMMER", "LIAO", "BHATT", "SP53", "ISO27001", "SP92", "ATTACK", "U1REF") else "Corpus" if re.fullmatch(r"A\d{3}", r_["Clave"]) else "Complementaria")])
ANNEX_HEAD = ["N.º", "Referencia", "DOI o enlace", "Título en el registro", "Año", "Registro", "¿Título coincide?", "Resuelve", "Origen"]
json.dump({"annex": ANNEX, "annex_head": ANNEX_HEAD, "title": TITLE, "authors": AUTH, "keywords": KEYWORDS, "blocks": blocks, "refs": refs, "ref_head": ref_head}, open(os.path.join(D, "documento.json"), "w", encoding="utf-8"), ensure_ascii=False)


def rh(rs):
    o = ""
    for r in rs:
        t = html.escape(r["t"])
        if r.get("b"):
            t = f"<b>{t}</b>"
        if r.get("i"):
            t = f"<i>{t}</i>"
        if r.get("c"):
            t = f"<code>{t}</code>"
        o += t
    return o


body = []
for b in blocks:
    k = b["k"]
    if k == "h1":
        body.append(f"<h1>{html.escape(b['t'])}</h1>")
    elif k == "h2":
        body.append(f"<h2>{html.escape(b['t'])}</h2>")
    elif k == "p":
        body.append(f"<p>{rh(b['r'])}</p>")
    elif k == "li":
        body.append(f"<ul><li>{rh(b['r'])}</li></ul>")
    elif k == "fig":
        data = base64.b64encode(open(os.path.join(FIG, b["file"]), "rb").read()).decode()
        body.append(f"<figure><div class=cap><b>Figura {b['n']}</b></div><div class=ti>{html.escape(b['title'])}</div><img src='data:image/png;base64,{data}'><div class=note><i>Nota.</i> {html.escape(b['note'])}</div></figure>")
    elif k == "tab":
        trs = ""
        for ri, r in enumerate(b["rows"]):
            tag = "th" if ri == 0 else "td"
            trs += "<tr>" + "".join(f"<{tag}>{rh(c)}</{tag}>" for c in r) + "</tr>"
        body.append(f"<div class=tb><div class=cap><b>Tabla {b['n']}</b></div><div class=ti>{html.escape(b['title'])}</div><table>{trs}</table><div class=note><i>Nota.</i> {html.escape(b['note'])}</div></div>")
def rl(r):
    t = html.escape(r["t"])
    if r.get("u"):
        return f'<a href="{t}">{t}</a>'
    return f"<i>{t}</i>" if r["i"] else t


reflist = "".join("<p class=ref>" + "".join(rl(r) for r in rr) + "</p>" for rr in refs)
CSS = """
@page{size:A4;margin:19mm 18mm 18mm 18mm}
*{box-sizing:border-box}
body{font-family:Cambria,'Noto Serif',Georgia,serif;font-size:10.5pt;line-height:1.42;color:#1b1b1b;margin:0}
.uni{font-family:'Segoe UI',Arial,sans-serif;font-size:8.6pt;letter-spacing:.09em;text-align:center;color:#444;text-transform:uppercase}
h0{display:block;font-size:17pt;font-weight:700;text-align:center;color:#141b34;line-height:1.24;margin:8pt 0 8pt;padding-bottom:9pt;border-bottom:2.2pt solid #1f3a7a}
.meta{font-family:'Segoe UI',Arial,sans-serif;font-size:8.8pt;text-align:center;color:#444;line-height:1.55;margin-bottom:6pt}
h1{font-size:13.5pt;color:#1f3a7a;margin:15pt 0 6pt;padding-bottom:2pt;border-bottom:.6pt solid #cfd6e4;page-break-after:avoid;letter-spacing:.02em}
h2{font-size:11.5pt;color:#1b1b1b;margin:10pt 0 4pt;page-break-after:avoid}
p{margin:0 0 6.5pt;text-align:justify}
ul{margin:0 0 4pt 16pt;padding:0}li{margin:0 0 3pt;text-align:justify}
code{font-family:Consolas,monospace;font-size:9.4pt}
.tb,figure{margin:8pt 0 10pt;page-break-inside:avoid}
.cap{font-size:10.5pt}.ti{font-style:italic;font-size:10.5pt;margin-bottom:4pt}
table{border-collapse:collapse;width:100%;font-family:'Segoe UI',Arial,sans-serif;font-size:8.7pt;line-height:1.3}
th{background:#eef2f9;color:#1b1b1b;text-align:left;font-weight:600;border:.5pt solid #cfd6e4;padding:3.5pt 5pt}
td{border:.5pt solid #d9dfeb;padding:3.2pt 5pt;vertical-align:top}
.note{font-size:9pt;margin-top:3pt}
figure img{width:90%;display:block;margin:0 auto}figure{margin-left:0;margin-right:0}
.anx{page-break-before:always}.ax{font-size:6.8pt;line-height:1.2;table-layout:fixed}.ax td,.ax th{padding:2pt 3pt;overflow-wrap:anywhere}.ax a{color:#1f3a7a}.ax th:nth-child(1){width:4%}.ax th:nth-child(2){width:14%}.ax th:nth-child(3){width:21%}.ax th:nth-child(4){width:29%}.ax th:nth-child(5){width:5%}.ax th:nth-child(6){width:7.5%}.ax th:nth-child(7){width:6.5%}.ax th:nth-child(8){width:5%}.ax th:nth-child(9){width:8%}
.ref a{color:#1f3a7a;text-decoration:underline}
.ref{font-size:10pt;line-height:2;padding-left:.5in;text-indent:-.5in;margin:0;text-align:left;overflow-wrap:anywhere}
"""
def _c(i, v):
    v_ = html.escape(str(v))
    return f'<a href="{v_}">{v_}</a>' if i == 2 and str(v).startswith("http") else v_


annex_html = "<div class=anx><h1>ANEXO B. DATOS DE REGISTRO DE LAS REFERENCIAS</h1><p>Consulta realizada el 10 de noviembre de 2026 en Crossref, DataCite y los sitios indicados.</p><table class=ax><thead><tr>" + "".join(f"<th>{h}</th>" for h in ANNEX_HEAD) + "</tr></thead><tbody>" + "".join("<tr>" + "".join(f"<td>{_c(i, v)}</td>" for i, v in enumerate(r)) + "</tr>" for r in ANNEX) + "</tbody></table></div>"
head = f"""<div class=uni>Universidad Privada de Tacna · Facultad de Ingeniería · Escuela Profesional de Ingeniería de Sistemas</div>
<h0>{html.escape(TITLE)}</h0>
<div class=meta><b>Autores:</b> {' · '.join(html.escape(a) for a in AUTH)}<br><b>Curso:</b> SI-985 Seguridad de Tecnología de Información &nbsp;|&nbsp; <b>Docente:</b> Dr. Renzo Alberto Taco Coayla &nbsp;|&nbsp; <b>Unidad II:</b> Diseño de la solución tecnológica &nbsp;|&nbsp; Tacna, 2026</div>"""
doc = f"<!doctype html><html lang=es><meta charset=utf-8><title>{html.escape(TITLE)}</title><style>{CSS}</style><body>{head}{''.join(body[:3])}<p><b>Palabras clave:</b> {html.escape(KEYWORDS)}</p>{''.join(body[3:])}<h1>{html.escape(ref_head)}</h1>{reflist}{annex_html}</body></html>"
hp = os.path.join(D, BASE + ".html")
open(hp, "w", encoding="utf-8").write(doc)
pdf_tmp = os.path.join(D, BASE + "_tmp.pdf")
chrome = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
subprocess.run([chrome, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={pdf_tmp}", "file:///" + hp.replace("\\", "/")], check=True, timeout=180, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
d = fitz.open(pdf_tmp)
for n, pg in enumerate(d, 1):
    r = pg.rect
    pg.draw_line((51, r.height - 40), (r.width - 51, r.height - 40), color=(.82, .84, .88), width=.5)
    pg.insert_text((51, r.height - 28), "Monitoreo distribuido con Wazuh en cuatro servidores", fontsize=8, fontname="helv", color=(.42, .42, .42))
    s = f"Documento técnico · Unidad II · Página {n}".replace("·", "-")
    pg.insert_text((r.width - 51 - fitz.get_text_length(s, fontname="helv", fontsize=8), r.height - 28), s, fontsize=8, fontname="helv", color=(.42, .42, .42))
d.set_metadata({"title": TITLE, "author": "; ".join(AUTH), "subject": "Unidad II", "keywords": KEYWORDS})
out = os.path.join(D, BASE + ".pdf")
d.save(out, garbage=3, deflate=True)
print("paginas", d.page_count)
ref_page = next(n for n, pg in enumerate(d, 1) if "REFERENCIAS BIBLIOGRÁFICAS" in pg.get_text())
anx_page = next(n for n, pg in enumerate(d, 1) if "ANEXO B. DATOS" in pg.get_text())
print("referencias desde pag", ref_page, "anexo desde pag", anx_page, "cuerpo", anx_page - 1)
d.close()
os.remove(pdf_tmp)
