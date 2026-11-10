import re, shutil, sys
sys.stdout.reconfigure(encoding="utf-8")
S = "C:/Users/Angel/AppData/Local/Temp/claude/1b5b5e12a59ef712/ce95a15d-d8ed-448e-8261-a82ff4e60839/scratchpad/"
C = "D:/ARTICULO_WAZUH/documento/contenido.txt"
shutil.copy2(C, C + ".antes_r6")
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


rep("y SSH solo con llaves desde la estación de gestión.", "y SSH solo con llaves desde la estación de gestión. La excepción es una cuenta señuelo con contraseña en SRV-WEB, limitada a la VLAN 99 mediante `Match Address` en `sshd_config`, necesaria para CP-07.")
rep("| Llaves SSH, respuesta activa |", "| Llaves SSH, cuenta señuelo solo para CP-07, respuesta activa |")
rep("| CP-07 | RF-08 | Fuerza bruta SSH desde Kali |", "| CP-07 | RF-08, RNF-11 | Fuerza bruta SSH desde Kali contra la cuenta señuelo |")
line("| RNF-02 | Seguridad |", "| RNF-02 | Seguridad: cifrado | Eventos agente-manager con estándar de cifrado avanzado (AES) y registro de agentes por seguridad de la capa de transporte (TLS) |")
rep("| RNF-09 | Sincronización | Desfase máximo de 1 s entre servidores |\n", "| RNF-09 | Sincronización | Desfase máximo de 1 s entre servidores |\n| RNF-10 | Seguridad: exposición | 0 servicios del SIEM accesibles desde VLAN 99 |\n| RNF-11 | Seguridad: acceso SSH | Administración solo desde 10.10.30.50; única excepción, la cuenta señuelo de SRV-WEB |\n")
line("| RNF-02 | FW-1, cifrado AES y TLS", "| RNF-02 | Cifrado AES y TLS | CP-10 | {ISO27001} |")
rep("| RNF-09 | FW-1 y clientes NTP | CP-16 | {SP92} |\n", "| RNF-09 | FW-1 y clientes NTP | CP-16 | {SP92} |\n| RNF-10 | FW-1 y VLAN 30 | CP-10 y CP-17 | {A004} |\n| RNF-11 | sshd y regla FW-03 | CP-07 y CP-10 | {ISO27001} |\n")
rep("| CP-10 | RNF-02 |", "| CP-10 | RNF-02, RNF-10, RNF-11 |")
rep("| CP-17 | RNF-02 |", "| CP-17 | RNF-10 |")
rep("9 requerimientos funcionales y 9 no funcionales", "9 requerimientos funcionales y 11 no funcionales")
rep("Cada 60 s, un servicio Python agrega las alertas nuevas por servidor,", "Cada 60 s, un servicio Python lee `alerts.json`, agrega las alertas nuevas por servidor,")
rep("y la regla FW-08 permanece desactivada durante los ataques.", "y durante los ataques el adaptador WAN de FW-1 se desconecta, lo que también impide el reenvío DNS hacia Internet.")
rep("| FW-08 desactivada en capturas | A.8.20 |", "| WAN de FW-1 desconectada en capturas | A.8.20 |")
rep("| FW-03 | SOC | 10.10.30.50 | VLAN 10 y 20 | TCP 22 | Permitir | Administración SSH |", "| FW-03 | SOC | 10.10.30.50 | VLAN 10 y 20; 10.10.30.1 | TCP 22; TCP 443 a FW-1 | Permitir | Administración SSH y consola de pfSense |")
rep("Los 26 flujos evaluados", "Los 27 flujos evaluados")
rep("Priorizar según el impacto en la organización es también la orientación de los enfoques de gestión de riesgo empresarial {A072}, y reducir la exposición mediante endurecimiento, segmentación y mínimo privilegio disminuye el riesgo de forma directa {A075}.", "Esta priorización según el impacto sigue ISO/IEC 27005 {ISO27005,A072}, y reducir la exposición mediante endurecimiento, segmentación y mínimo privilegio disminuye el riesgo {SP30,A075}.")
rep("ubica los controles por zonas y fronteras de confianza.", "ubica los controles por zonas y fronteras de confianza. Estos controles cubren las funciones Proteger y Detectar de NIST CSF 2.0, y la sección 10.3 completa las restantes.")
rep("La operación diaria comprende revisar el estado de los agentes, atender alertas de nivel 10 o superior y alertas del modelo, y comprobar el espacio en disco. El mantenimiento semanal incluye parches, verificación de respaldos y revisión de reglas ruidosas. La optimización", "- **Diario (analista de turno):** 1) revisar el estado de los agentes; 2) atender las alertas de nivel 10 o superior y las del modelo; 3) comprobar el espacio en disco.\n- **Semanal (administrador del SIEM):** 1) aplicar parches; 2) verificar respaldos; 3) revisar reglas ruidosas.\n\nLa optimización")
rep("- **OE1.** Sintetizar 80 artículos para extraer decisiones de arquitectura, correlación y evaluación aplicables al diseño.", "- **OE1.** Identificar en 80 artículos al menos 10 decisiones de arquitectura, correlación y evaluación aplicables al diseño.")
rep("- **OE6.** Planificar la implementación, las pruebas y la factibilidad de la Unidad III.", "- **OE6.** Planificar la implementación, las pruebas y la factibilidad de la Unidad III en seis semanas, con criterios de aceptación medibles en cada prueba.")
rep("con experiencia previa en Wazuh y en laboratorios virtualizados.", "con experiencia previa en Wazuh y en laboratorios virtualizados, como el prototipo de la Unidad I {U1REF}.")
rep("Estos resultados provienen de datos públicos y deberán confirmarse con las capturas propias de la Unidad III.", "Estos resultados provienen de datos públicos y deberán confirmarse con las capturas propias de la Unidad III. Las principales limitaciones son los roles deducidos de rutas de registro, las etiquetas temporales y la ausencia de una organización real.")
rep("@nota Elaboración propia a partir de Anampa Pancca et al. (2026).", "@nota Elaboración propia a partir de Anampa Pancca et al. (2026). Las referencias heredadas de esa unidad se identifican en el Anexo B.")
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
 ('''        sub = [x for x in p.split("-") if x]''', '''        if p in ("de", "do", "da", "dos", "das", "del"):
            res.append(p)
            continue
        sub = [x for x in p.split("-") if x]'''),
 ('''cr["A078"].update(page="6768-6776")''', '''cr["A078"].update(page="6768-6776")
cr["A039"].update(page="239-251")
cr["A052"].update(page="1121-1130")'''),
 ('''("i", "ICACNC 2026 Proceedings")''', '''("i", "International Conference on AI, Cybersecurity, and Next-Gen Computing (ICACNC 2026) Proceedings")'''),
 ('''    if i == "A005":''', '''    if i == "A041":
        runs = [("n", f"{apa_auth(a)} ({y}). "), ("i", title.replace(" [Preprint]", "").rstrip(".")), ("n", " [Preprint]. Research Square. "), ("n", doi)]
    if i == "A005":'''),
 ('''["National Institute of Standards and Technology"], "NIST", 2024''', '''["National Institute of Standards and Technology"], "National Institute of Standards and Technology", 2024'''),
 ('''"Organismo Supervisor de la Inversión en Energía y Minería [Osinergmin]", 2026''', '''"Organismo Supervisor de la Inversión en Energía y Minería", 2026'''),
 ('''CITE_NAME = {"A045": "Landauer, Skopik, Frank et al."}''', '''CITE_NAME = {"A045": "Landauer, Skopik, Frank et al.", "A077": "M. A. Islam", "A037": "M. R. Islam y Rafique"}'''),
 ('''    x_["runs"] = [x_["runs"][0]] + [''', '''    _nr = []
    for k_, b_ in x_["runs"]:
        m_ = re.search(r" (\\(versión[^)]*\\) )?\\[Conjunto de datos\\]$", b_) if k_ == "i" else None
        if m_:
            _nr += [("i", b_[:m_.start()]), ("n", b_[m_.start():])]
        else:
            _nr.append((k_, b_))
    x_["runs"] = _nr
    x_["runs"] = [x_["runs"][0]] + ['''),
])
patch(S + "verify_refs.py", [
 ('''doc_title = "".join(b for _, b in x["runs"][:1]).split("). ", 1)[1].strip()''', '''doc_title = "".join(b for _, b in x["runs"][:1]).split("). ", 1)[1].strip() or x["runs"][1][1]'''),
 ('''doc_title = x["runs"][1][1]''', '''doc_title = x["runs"][1][1]''') if False else ('''res = dict(N=n,''', '''res = dict(N=n,'''),
])
patch(S + "valida_red.py", [
 (''' ("FW-04", L("V10", "V20", "V30", "V99"), "FW",''', ''' ("FW-03", "10.10.30.50", "10.10.30.1", {("tcp", 443)}, "allow"),
 ("FW-04", L("V10", "V20", "V30", "V99"), "FW",'''),
 ('''("SSH admin a web", "ADM", "WEB", "tcp", 22, "capture", "allow"),''', '''("Consola de pfSense", "ADM", "FW30", "tcp", 443, "capture", "allow"), ("SSH admin a web", "ADM", "WEB", "tcp", 22, "capture", "allow"),'''),
])
patch(S + "build.py", [
 ('''ref_head = f"{h1}. REFERENCIAS BIBLIOGRÁFICAS (FORMATO APA 7.ª EDICIÓN)"''', '''ref_head = f"{h1}. REFERENCIAS BIBLIOGRÁFICAS"'''),
 ('''"REFERENCIAS BIBLIOGRÁFICAS (FORMATO" in pg.get_text()''', '''"REFERENCIAS BIBLIOGRÁFICAS" in pg.get_text()'''),
 ('''r_["Resuelve"] or "—"])''', '''r_["Resuelve"] or "—", ("Unidad I" if r_["Clave"] in ("SOMMER", "LIAO", "BHATT", "SP53", "ISO27001", "SP92", "ATTACK", "U1REF") else "Corpus" if re.fullmatch(r"A\\d{3}", r_["Clave"]) else "Complementaria")])'''),
 ('''"¿Título coincide?", "Resuelve"]''', '''"¿Título coincide?", "Resuelve", "Origen"]'''),
 ('''.ax th:nth-child(3){width:23%}.ax th:nth-child(4){width:34%}.ax th:nth-child(5){width:5%}.ax th:nth-child(6){width:8%}.ax th:nth-child(7){width:6.5%}.ax th:nth-child(8){width:5.5%}''', '''.ax th:nth-child(3){width:21%}.ax th:nth-child(4){width:29%}.ax th:nth-child(5){width:5%}.ax th:nth-child(6){width:7.5%}.ax th:nth-child(7){width:6.5%}.ax th:nth-child(8){width:5%}.ax th:nth-child(9){width:8%}'''),
 ('''figure img{width:100%;display:block}''', '''figure img{width:90%;display:block;margin:0 auto}'''),
])
patch(S + "mkdocx.js", [
 ('''const W2 = [420, 1500, 2300, 3200, 470, 780, 520, 448];''', '''const W2 = [400, 1400, 2100, 2800, 450, 740, 500, 440, 808];'''),
])
d = open(S + "diagrams.py", encoding="utf-8").read()
m = re.search(r"f, a = canvas\(7\.4, 2\.1\)\n.*?save\(f, \"d_flujo_info\.png\"\)", d, re.S)
assert m
new = '''f, a = canvas(7.4, 2.5)
R1 = [(2, "Agentes", ["Leen registros", "de cada servidor"]), (22, "Manager", ["TCP 1514, AES", "Reglas y alertas"]), (42, "alerts.json", ["Con Suricata", "(eve.json)"]), (62, "Indexer", ["Consulta por", "90 días"]), (82, "Analista", ["Triaje y", "respuesta"])]
for k, (x, t, l) in enumerate(R1):
    box(a, x, 54, 16, 40, t, l, fs=7.2, ls=6.2, step=10)
    if k < 4:
        arrow(a, (x + 16, 74), (x + 20, 74))
box(a, 42, 6, 16, 34, "Servicio ML", ["Lee alerts.json", "cada 60 s"], ec=GREEN, tc="#10734f", fs=7.2, ls=6.2, step=9)
arrow(a, (50, 54), (50, 40), color="#10734f")
a.plot([42, 30], [23, 23], color="#10734f", lw=1, ls=(0, (3, 2)))
a.annotate("", xy=(30, 54), xytext=(30, 23), arrowprops=dict(arrowstyle="-|>", color="#10734f", lw=1, ls=(0, (3, 2)), shrinkA=0, shrinkB=0))
a.text(19, 23, "Registro local que", ha="center", va="center", fontsize=6.3, color="#10734f")
a.text(19, 15, "lee el manager", ha="center", va="center", fontsize=6.3, color="#10734f")
save(f, "d_flujo_info.png")'''
d = d[:m.start()] + new + d[m.end():]
for a_, b_ in [('box(a, 3.5, 9.5, 18, 8.5, "NIC2 SRV-SIEM, sin IP", [], ec=ORANGE, tc=ORANGE, fs=6.1)', 'box(a, 3.5, 9.5, 18, 8.5, "NIC2, sin IP", [], ec=ORANGE, tc=ORANGE, fs=6.8)'),
               ('"Hardening CIS (A.8.8)", "FIM y agente (A.8.16)", "SSH con llaves (A.8.5)"', '"Hardening CIS (A.8.9)", "FIM y agente (A.8.16)", "SSH: llaves y señuelo (A.8.5)"')]:
    assert d.count(a_) == 1, a_[:40]
    d = d.replace(a_, b_)
open(S + "diagrams.py", "w", encoding="utf-8").write(d)
print("OK")
