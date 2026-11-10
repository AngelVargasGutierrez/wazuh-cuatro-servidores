S = "C:/Users/Angel/AppData/Local/Temp/claude/1b5b5e12a59ef712/ce95a15d-d8ed-448e-8261-a82ff4e60839/scratchpad/"


def patch(path, pairs):
    t = open(path, encoding="utf-8").read()
    for a, b in pairs:
        assert t.count(a) == 1, (path[-16:], t.count(a), a[:70])
        t = t.replace(a, b)
    open(path, "w", encoding="utf-8").write(t)


patch(S + "build.py", [
 ('''r_["Titulo_registrado"] or "—", str(r_["Anio_registrado"] or "—"), r_["Fuente"], ("Sí" if sim_ and float(sim_) >= .75 else "No aplica" if not sim_ else "No"), r_["Resuelve"] or "—", r_["Fecha"]])''',
  '''re.sub(r"</?[a-zA-Z]+>", "", html.unescape(html.unescape(html.unescape(r_["Titulo_registrado"])))).replace("Informe de la Unidad I del grupo", "") or "—", str(r_["Anio_registrado"] or "—"), r_["Fuente"].replace("Informe de la Unidad I del grupo", "Informe propio"), ("Sí" if sim_ and float(sim_) >= .75 else "No aplica" if not sim_ else "No"), r_["Resuelve"] or "—"])'''),
 ('''ANNEX_HEAD = ["N.º", "Referencia", "DOI o enlace", "Título en el registro", "Año", "Registro consultado", "Título coincide", "Resuelve", "Consulta"]''',
  '''ANNEX_HEAD = ["N.º", "Referencia", "DOI o enlace", "Título en el registro", "Año", "Registro", "¿Título coincide?", "Resuelve"]'''),
 ('''.ax th:nth-child(1){width:4%}.ax th:nth-child(2){width:14%}.ax th:nth-child(3){width:22%}.ax th:nth-child(4){width:30%}.ax th:nth-child(5){width:5%}.ax th:nth-child(6){width:8%}.ax th:nth-child(7){width:6%}.ax th:nth-child(8){width:5%}.ax th:nth-child(9){width:6%}''',
  '''.ax th:nth-child(1){width:4%}.ax th:nth-child(2){width:14%}.ax th:nth-child(3){width:23%}.ax th:nth-child(4){width:34%}.ax th:nth-child(5){width:5%}.ax th:nth-child(6){width:8%}.ax th:nth-child(7){width:6.5%}.ax th:nth-child(8){width:5.5%}'''),
])
patch(S + "mkdocx.js", [
 ('''const W2 = [420, 1500, 2400, 2700, 470, 750, 500, 450, 448];''', '''const W2 = [420, 1500, 2300, 3200, 470, 780, 520, 448];'''),
])
patch(S + "diagrams.py", [
 ('''box(a, 3.5, 10, 18, 7.5, "NIC2 de SRV-SIEM", [], ec=ORANGE, tc=ORANGE, fs=6.6)
a.text(12.5, 18.6, "Captura de toda la VLAN 10, sin IP", ha="center", fontsize=5.6, color=ORANGE)
arrow(a, (21.5, 13.5), (53.5, 22), "Réplica a Suricata", color=ORANGE, ls=(0, (3, 2)), offset=(0, -3.2), fs=6.5)''',
  '''box(a, 3.5, 9.5, 18, 8.5, "NIC2 SRV-SIEM, sin IP", [], ec=ORANGE, tc=ORANGE, fs=6.1)
arrow(a, (21.5, 13.5), (53.5, 22), "Réplica de la VLAN 10", color=ORANGE, ls=(0, (3, 2)), offset=(0, -3.2), fs=6.3)'''),
 ('''"AES y TLS (A.8.24)", "Registros, NTP (A.8.15, A.8.17)", "Reglas y puntuación ML"]''', '''"AES y TLS (A.8.24)", "Registros (A.8.15)", "NTP (A.8.17)", "Reglas y puntuación ML"]'''),
 ('''a.text(x + 11.4, 59.5 - i * 6.8, l,''', '''a.text(x + 11.4, 59.5 - i * 6.2, l,'''),
])
patch(S + "charts.py", [
 ('''a.set_yticks(y, names); a.set_title(t, fontsize=9, color=INK, loc="left"); a.set_xlim(0, .56)''', '''a.set_yticks(y, names); a.set_title(t, fontsize=9, color=INK, loc="left", pad=8); a.set_xlim(0, .56); a.set_ylim(-.55, len(order) - .25)'''),
])
print("OK")
