import re, shutil, sys
sys.stdout.reconfigure(encoding="utf-8")
S = "C:/Users/Angel/AppData/Local/Temp/claude/1b5b5e12a59ef712/ce95a15d-d8ed-448e-8261-a82ff4e60839/scratchpad/"
C = "D:/ARTICULO_WAZUH/documento/contenido.txt"
shutil.copy2(C, C + ".antes_r4")
s = open(C, encoding="utf-8").read()
FAILS = []


def rep(a, b):
    global s
    if s.count(a) != 1:
        FAILS.append((s.count(a), a[:90]))
        return
    s = s.replace(a, b)


def line(prefix, new):
    global s
    m = re.findall(r"^" + re.escape(prefix) + r".*$", s, re.M)
    if len(m) != 1:
        FAILS.append((len(m), prefix))
        return
    s = s.replace(m[0], new)


def block(key, new):
    global s
    m = re.search(r"@tabla " + key + r"\|.*?\n@nota[^\n]*\n", s, re.S)
    if not m:
        FAILS.append(("bloque", key))
        return
    s = s[:m.start()] + new.strip() + "\n" + s[m.end():]


line("| RNF-02 | Seguridad |", "| RNF-02 | Seguridad | Eventos agente-manager con estándar de cifrado avanzado (AES) y registro de agentes por seguridad de la capa de transporte (TLS); 0 servicios del SIEM accesibles desde VLAN 99; SSH de administración solo desde 10.10.30.50, salvo SRV-WEB, expuesto a VLAN 99 para CP-07 |")
rep("por un analista del grupo |", "por un integrante que no entrenó el modelo |")
rep("| Mantener servidor propio | A | R | R | R |", "| Mantener servidor propio | R/A | R | R | R |")
rep("Las tareas repetitivas se automatizarán con Ansible, como en otros despliegues {A019}.", "La automatización con Ansible, usada en otros despliegues {A019}, queda como mejora posterior y no forma parte de la Unidad III.")
rep("| I-05 | Aplicar hardening y respaldos | Todos | I-04 | Lista de verificación |", "| I-05 | Aplicar hardening y respaldos | Todos | I-04 | Lista de verificación, Git privado y copia en la nube |")
rep("Restaurar SRV-SIEM desde la copia fuera del equipo", "Restaurar SRV-SIEM desde el medio extraíble")
rep("Las reglas y scripts se versionan en un repositorio Git privado.", "Se respaldan la configuración, las reglas, los modelos y las instantáneas del indexer, no el disco virtual completo. La clave de la copia en la nube la custodia el administrador del SIEM. Las reglas y scripts se versionan en un repositorio Git privado.")
rep("en escala de 1 a 5:", "en escala de 1 a 5 (1 excepcional o mínimo, 2 improbable o menor, 3 posible o moderado, 4 probable o grave, 5 casi seguro o crítico):")
m = re.search(r"^\| R-11 \|.*$", s, re.M)
s = s[:m.end()] + "\n| R-12 | Abuso del adaptador de captura en la DMZ | 2 | 4 | 8 Medio | Sin IP, sin ARP y sin reenvío | A.8.20 | 1 × 4 = 4 Bajo | SIEM |" + s[m.end():]
rep("R-09 ya tiene la probabilidad mínima, por lo que su valor no se reduce.", "Los controles reducen la probabilidad y el impacto se mantiene; R-09 ya tiene la probabilidad mínima.")
rep("once reglas de cortafuegos y once riesgos tratados.", "once reglas de cortafuegos y doce riesgos tratados.")
block("fw", """@tabla fw|Reglas del cortafuegos FW-1 por interfaz
| ID | Interfaz | Origen | Destino | Puerto | Acción | Propósito |
| FW-01 | DMZ, SERV | VLAN 10 y 20 | 10.10.30.10 | TCP 1514, 1515 | Permitir | Agentes hacia manager y registro |
| FW-02 | DMZ, SERV, SOC | VLAN 10, 20 y 30 | FW-1 | TCP y UDP 53 | Permitir | Resolución de nombres con reenvío |
| FW-03 | SOC | 10.10.30.50 | VLAN 10 y 20 | TCP 22 | Permitir | Administración SSH |
| FW-04 | Todas | VLAN 10, 20, 30 y 99 | FW-1 | UDP 123 | Permitir | Sincronización NTP |
| FW-05 | ADV | VLAN 99 | 10.10.10.10 | TCP 22, 80, 443 | Permitir | Superficie web y fuerza bruta (CP-07) |
| FW-06 | ADV | VLAN 99 | 10.10.10.20 | TCP 25, 143, 993 | Permitir | Superficie de correo de prueba |
| FW-07 | DMZ | VLAN 10 | 10.10.20.10 | TCP 389, 636; TCP y UDP 53 | Permitir | Autenticación y DNS |
| FW-08 | DMZ, SERV, SOC | VLAN 10, 20 y 30 | WAN | TCP 80, 443 | Permitir temporal | Instalación y parches; desactivada en capturas |
| FW-09 | DMZ | 10.10.10.10 | 10.10.99.10 | TCP 4444; UDP 53 | Permitir temporal | Shell inversa y exfiltración simulada; solo en pruebas |
| FW-10 | ADV | VLAN 99 | VLAN 20 y 30 | Todos | Denegar | Aislar al adversario |
| FW-11 | Todas | Cualquiera | Cualquiera | Todos | Denegar y registrar | Regla por defecto |
@nota Elaboración propia. Interfaces de FW-1: WAN, DMZ (VLAN 10), SERV (VLAN 20), SOC (VLAN 30) y ADV (VLAN 99). El adversario llega a la VLAN 20 solo por movimiento lateral desde la DMZ, parte del escenario de prueba.""")
rep("para que no actúe como puente con la DMZ.", "para que no actúe como puente con la DMZ. La consola web de pfSense solo se atiende en la interfaz SOC desde 10.10.30.50. SRV-AUT es autoritativo para el dominio interno y FW-1 reenvía las consultas externas.")
rep("tiene ARP desactivado", "tiene desactivado el protocolo de resolución de direcciones (ARP)")
rep("mediante una política ISM del indexer", "mediante una política de gestión de estados de índice (ISM) del indexer")
rep("Tarifa BT5B de Electrosur", "Tarifa BT5B (baja tensión con medición simple) de Electrosur")
rep("La {{T:raci}} distribuye las responsabilidades.", "La matriz responsable, aprueba, consultado, informado (RACI) de la {{T:raci}} distribuye las responsabilidades.")
rep("matriz responsable, aprueba, consultado, informado (RACI), el inventario", "matriz RACI, el inventario")
rep("orquestación, automatización y respuesta de seguridad (SOAR) como Shuffle o n8n", "SOAR como Shuffle o n8n")
rep("La {{T:alt}} recoge el resultado.", "La {{T:alt}} recoge el resultado; SOAR designa las plataformas de orquestación, automatización y respuesta de seguridad.")
rep("| monitoreo de integridad de archivos (FIM) de Wazuh |", "| FIM de Wazuh |")
rep("| RF-04 | Detectar cambios en archivos críticos |", "| RF-04 | Detectar cambios en archivos críticos mediante monitoreo de integridad de archivos (FIM) |")
rep("por lo que el objetivo se cumplió con un margen útil, aunque con baja sensibilidad por ventana.", "por lo que el objetivo se cumplió, con baja sensibilidad por ventana y con la reserva de que la significación no resiste una corrección por comparaciones múltiples.")
s = s.replace("número de servidores activos", "número de roles con alertas")
rep("@tabla coact|Coactividad de servidores y proporción", "@tabla coact|Coactividad de roles y proporción")
rep("| Servidores con alertas | Ventanas |", "| Roles con alertas | Ventanas |")
rep("**Regresión logística multiservidor**", "**Regresión logística multifuente**")
rep("Precisión promedio según los servidores considerados", "Precisión promedio según los roles considerados")
rep("La {{F:seg}} organiza los controles por capas.", "La {{F:seg}} ubica los controles por zonas y fronteras de confianza.")
rep("|Diagrama de seguridad por capas y controles asociados|", "|Diagrama de seguridad por zonas de confianza y controles|")
rep(" Cada referencia incluye su DOI o enlace activo para que pueda comprobarse directamente.", " El Anexo B lista los datos de registro consultados para cada referencia.")
block("gantt", """@tabla gantt|Cronograma de la Unidad III por medias semanas
| Actividad | 1a | 1b | 2a | 2b | 3a | 3b | 4a | 4b | 5a | 5b | 6a | 6b |
| I-01 e I-02 | ■ | ■ |  |  |  |  |  |  |  |  |  |  |
| I-03 e I-04 |  |  | ■ | ■ |  |  |  |  |  |  |  |  |
| I-05 |  |  |  |  | ■ |  |  |  |  |  |  |  |
| I-06 |  |  |  |  |  | ■ |  |  |  |  |  |  |
| I-07 |  |  |  |  |  |  | ■ | ■ |  |  |  |  |
| I-08 |  |  |  |  |  |  |  |  | ■ |  |  |  |
| I-09 |  |  |  |  |  |  |  |  |  | ■ | ■ |  |
| Holgura |  |  |  |  |  |  |  |  |  |  |  | ■ |
@nota Elaboración propia. 1a y 1b indican la primera y segunda mitad de cada semana de la Unidad III.""")
if FAILS:
    print("\n".join(map(str, FAILS)))
    sys.exit(1)
open(C, "w", encoding="utf-8").write(s)


def patch(path, pairs):
    t = open(path, encoding="utf-8").read()
    for a, b in pairs:
        assert t.count(a) == 1, (path[-16:], t.count(a), a[:70])
        t = t.replace(a, b)
    open(path, "w", encoding="utf-8").write(t)


patch(S + "refs.py", [
 ('''    if i == "A005":''', '''    if c.get("type") == "proceedings-article" and i != "A005":
        pb = c.get("publisher") or ""
        pb = "SBC" if "Brasileira" in pb or "SBC" in pb else "ACM" if "Computing Machinery" in pb or pb.startswith("ACM") else "IEEE" if "IEEE" in pb else pb
        runs = [runs[0], ("n", "En "), ("i", cont), ("n", (f" (pp. {pg}). " if pg else ". ") + f"{pb}. "), ("n", doi)]
    if i == "A005":'''),
 ('''"Dataset and scripts for timeliness fails before compute: Lessons for benchmarking distributed SIEM deployments [Conjunto de datos]"''', '''"Dataset and scripts for timeliness fails before compute: Lessons for benchmarking distributed SIEM deployments (versión 2.0.0) [Conjunto de datos]"'''),
 ('''items.sort(key=lambda x: x["sort"])''', '''items.sort(key=lambda x: x["sort"])
for x_ in items:
    a0_ = x_["runs"][0][1]
    head_, sep_, tail_ = a0_.partition("). ")
    x_["runs"][0] = (x_["runs"][0][0], head_.replace(", & ", " y ") + sep_ + tail_)
    x_["runs"] = [x_["runs"][0]] + [(k_, re.sub(r"(,\\s|pp\\. )(\\w*\\d+)-(\\w*\\d+)", r"\\1\\2–\\3", b_) if not b_.startswith("http") else b_) for k_, b_ in x_["runs"][1:]]'''),
])

patch(S + "diagrams.py", [
 ('''a.text(87, 57.6, "Agentes: AES, TCP 1514"''', '''a.text(12, 58.5, "Agentes: AES, TCP 1514"'''),
 ('''arrow(a, (41, 42), (41, 38), color="#10734f"); arrow(a, (59, 38), (59, 42), color="#10734f")''', '''arrow(a, (34, 42), (34, 38), color="#10734f"); arrow(a, (42, 38), (42, 42), color="#10734f")'''),
 ('''arrow(a, (24, 26.5), (53.5, 26.5), "Réplica de toda la VLAN 10 a Suricata", color=ORANGE, ls=(0, (3, 2)), offset=(0, -4), fs=6.5)''', '''box(a, 3.5, 10, 18, 7.5, "NIC2 de SRV-SIEM", [], ec=ORANGE, tc=ORANGE, fs=6.6)
a.text(12.5, 18.6, "Captura de toda la VLAN 10, sin IP", ha="center", fontsize=5.6, color=ORANGE)
arrow(a, (21.5, 13.5), (53.5, 22), "Réplica a Suricata", color=ORANGE, ls=(0, (3, 2)), offset=(0, -3.2), fs=6.5)
a.text(62.5, 12, "Red solo anfitrión", ha="center", fontsize=6.6, color=MUTE)'''),
 ('''("Anfitrión", ".50")''', '''("Anfitrión", ".50")'''),
])
d = open(S + "diagrams.py", encoding="utf-8").read()
m = re.search(r"# Seguridad\n.*?save\(f, \"d_seguridad.png\"\)\n", d, re.S)
assert m
new = """# Seguridad
f, a = canvas(7.4, 4.4)
a.add_patch(Rectangle((2, 80), 96, 14, fc="#fff6ef", ec=ORANGE, lw=1.2))
a.text(50, 89.7, "Frontera FW-1: denegación por defecto y reglas FW-01 a FW-11", ha="center", va="center", fontsize=8.2, fontweight="bold", color=ORANGE)
a.text(50, 84, "ISO/IEC 27001:2022, A.8.20 · A.8.22", ha="center", va="center", fontsize=6.9, color=MUTE)
Z = [("VLAN 99: Adversario", "No confiable", ["Sin acceso a VLAN 20 y 30", "Solo superficie de prueba", "Red sin Internet en capturas"], ORANGE),
     ("VLAN 10: DMZ", "Confianza baja", ["Hardening CIS (A.8.8)", "FIM y agente (A.8.16)", "SSH con llaves (A.8.5)", "Captura pasiva a Suricata"], BLUE),
     ("VLAN 20: Servicios", "Confianza media", ["Hardening CIS (A.8.9)", "auditd y agente", "Mínimo privilegio (A.5.15)", "Solo LDAP y DNS desde DMZ"], GREEN),
     ("VLAN 30: SOC", "Confianza alta", ["RBAC en dashboard (A.8.2)", "nftables en SRV-SIEM", "AES y TLS (A.8.24)", "Registros, NTP (A.8.15, A.8.17)", "Reglas y puntuación ML"], NAVY)]
for k, (t, tr, ls_, col) in enumerate(Z):
    x = 2 + k * 24.4
    a.add_patch(Rectangle((x, 26), 22.8, 50, fc="white", ec=col, lw=1.2))
    a.add_patch(Rectangle((x, 69), 22.8, 7, fc=col, ec=col))
    a.text(x + 11.4, 72.5, t, ha="center", va="center", color="white", fontsize=7.2, fontweight="bold")
    a.text(x + 11.4, 65.5, tr, ha="center", va="center", color=col, fontsize=7, fontstyle="italic")
    for i, l in enumerate(ls_):
        a.text(x + 11.4, 59.5 - i * 6.8, l, ha="center", va="center", fontsize=6.2, color=INK)
a.add_patch(Rectangle((2, 4), 96, 18, fc="#f7f7f5", ec=MUTE, lw=1.1))
a.text(50, 16.8, "Respuesta y recuperación: respaldo 3-2-1 (A.8.13) · RPO 24 h · RTO 4 h · incidentes (A.5.24 a A.5.29)", ha="center", va="center", fontsize=7, color=INK)
a.text(50, 9.6, "Equipo anfitrión fuera de las zonas: punto único de falla (R-11). MFA solo en producción.", ha="center", va="center", fontsize=6.8, color=MUTE)
save(f, "d_seguridad.png")
"""
d = d[:m.start()] + new + d[m.end():]
a_ = '''save(f, "d_flujo_info.png")'''
assert d.count(a_) == 1
d = d.replace(a_, '''a.plot([73.4, 73.4, 24.3, 24.3], [85, 96, 96, 85], color="#10734f", lw=1, ls=(0, (3, 2)))
a.annotate("", xy=(24.3, 85), xytext=(24.3, 90), arrowprops=dict(arrowstyle="-|>", color="#10734f", lw=1, shrinkA=0, shrinkB=0))
a.text(48.8, 96, "Registro local que lee el manager", ha="center", va="center", fontsize=6.4, color="#10734f", bbox=dict(fc="white", ec="none", pad=.6))
save(f, "d_flujo_info.png")''')
open(S + "diagrams.py", "w", encoding="utf-8").write(d)

patch(S + "charts.py", [
 ('''    a.hlines(y, 0, v, color=BLUE, lw=2.2)\n''', ''),
 ('''a.text(val + sd + .012, yy + .18, f"{val:.2f}".replace(".", ","), fontsize=7.8, color=INK, va="center")''', '''a.text(val, yy + .3, f"{val:.2f}".replace(".", ","), fontsize=7.8, color=INK, va="center", ha="center")'''),
 ('''"Solo web", "Cuatro servidores"]''', '''"Solo web", "Cuatro roles"]'''),
])

patch(S + "build.py", [
 ('''json.dump({"title": TITLE,''', '''import csv as _csv
_rows = list(_csv.DictReader(open(r"D:\\ARTICULO_WAZUH\\documento\\Anexo_B_Verificacion_de_Referencias.csv", encoding="utf-8-sig"), delimiter=";"))
ANNEX = []
for r_ in _rows:
    ref = r_["Referencia"]
    aut = ref.split(" (")[0].split(",")[0]
    year = re.search(r"\\((\\d{4}[a-z]?|s\\. f\\.[^)]*)\\)", ref)
    link = "https://doi.org/" + r_["DOI"] if r_["DOI"] else next(iter(re.findall(r"https?://\\S+", ref)), "")
    sim_ = r_["Similitud_titulo"]
    ANNEX.append([r_["N"], f"{aut}, {year.group(1) if year else ''}", link, r_["Titulo_registrado"] or "—", str(r_["Anio_registrado"] or "—"), r_["Fuente"], ("Sí" if sim_ and float(sim_) >= .75 else "No aplica" if not sim_ else "No"), r_["Resuelve"] or "—", r_["Fecha"]])
ANNEX_HEAD = ["N.º", "Referencia", "DOI o enlace", "Título en el registro", "Año", "Registro consultado", "Título coincide", "Resuelve", "Consulta"]
json.dump({"annex": ANNEX, "annex_head": ANNEX_HEAD, "title": TITLE,'''),
 ('''{reflist}</body></html>"''', '''{reflist}{annex_html}</body></html>"'''),
 ('''head = f"""<div class=uni>''', '''def _c(i, v):
    v_ = html.escape(str(v))
    return f'<a href="{v_}">{v_}</a>' if i == 2 and str(v).startswith("http") else v_


annex_html = "<div class=anx><h1>ANEXO B. DATOS DE REGISTRO DE LAS REFERENCIAS</h1><p>Consulta realizada el 10 de noviembre de 2026 en Crossref, DataCite y los sitios indicados.</p><table class=ax><thead><tr>" + "".join(f"<th>{h}</th>" for h in ANNEX_HEAD) + "</tr></thead><tbody>" + "".join("<tr>" + "".join(f"<td>{_c(i, v)}</td>" for i, v in enumerate(r)) + "</tr>" for r in ANNEX) + "</tbody></table></div>"
head = f"""<div class=uni>'''),
 ('''.ref a{color''', '''.anx{page-break-before:always}.ax{font-size:6.8pt;line-height:1.2;table-layout:fixed}.ax td,.ax th{padding:2pt 3pt;overflow-wrap:anywhere}.ax a{color:#1f3a7a}.ax th:nth-child(1){width:4%}.ax th:nth-child(2){width:14%}.ax th:nth-child(3){width:22%}.ax th:nth-child(4){width:30%}.ax th:nth-child(5){width:5%}.ax th:nth-child(6){width:8%}.ax th:nth-child(7){width:6%}.ax th:nth-child(8){width:5%}.ax th:nth-child(9){width:6%}
.ref a{color'''),
 ('''ref_page = next(n for n, pg in enumerate(d, 1) if "REFERENCIAS BIBLIOGRÁFICAS (FORMATO" in pg.get_text())
print("referencias desde pag", ref_page)''', '''ref_page = next(n for n, pg in enumerate(d, 1) if "REFERENCIAS BIBLIOGRÁFICAS (FORMATO" in pg.get_text())
anx_page = next(n for n, pg in enumerate(d, 1) if "ANEXO B. DATOS" in pg.get_text())
print("referencias desde pag", ref_page, "anexo desde pag", anx_page, "cuerpo", anx_page - 1)'''),
])

patch(S + "mkdocx.js", [
 ('''const footer = new Footer(''', '''{
  const W2 = [420, 1500, 2400, 2700, 470, 750, 500, 450, 448];
  const s2 = W2.reduce((a, b) => a + b, 0); W2[3] += W - s2;
  ch.push(new Paragraph({ heading: HeadingLevel.HEADING_1, pageBreakBefore: true, children: [new TextRun({ text: "ANEXO B. DATOS DE REGISTRO DE LAS REFERENCIAS" })] }));
  ch.push(new Paragraph({ spacing: { after: 100 }, children: [new TextRun({ text: "Consulta realizada el 10 de noviembre de 2026 en Crossref, DataCite y los sitios indicados.", font: SERIF, size: 19 })] }));
  const cell = (kids, w, head) => new TableCell({ width: { size: w, type: WidthType.DXA }, borders, margins: { top: 20, bottom: 20, left: 40, right: 40 }, shading: head ? { type: ShadingType.CLEAR, fill: "EEF2F9", color: "auto" } : undefined, children: [new Paragraph({ spacing: { after: 0, line: 200 }, children: kids })] });
  ch.push(new Table({ width: { size: W, type: WidthType.DXA }, columnWidths: W2, rows: [
    new TableRow({ tableHeader: true, children: J.annex_head.map((h, i) => cell([new TextRun({ text: h, bold: true, font: SANS, size: 13 })], W2[i], true)) }),
    ...J.annex.map(r => new TableRow({ cantSplit: true, children: r.map((v, i) => cell([i === 2 && String(v).startsWith("http") ? new ExternalHyperlink({ link: v, children: [new TextRun({ text: v, font: SANS, size: 12, color: NAVY, underline: {} })] }) : new TextRun({ text: String(v), font: SANS, size: 12 })], W2[i], false)) })),
  ] }));
}
const footer = new Footer('''),
])
print("OK")
