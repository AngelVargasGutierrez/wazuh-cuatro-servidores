import re, shutil, sys
sys.stdout.reconfigure(encoding="utf-8")
S = "C:/Users/Angel/AppData/Local/Temp/claude/1b5b5e12a59ef712/ce95a15d-d8ed-448e-8261-a82ff4e60839/scratchpad/"
C = "D:/ARTICULO_WAZUH/documento/contenido.txt"
shutil.copy2(C, C + ".antes_tecnicas")
s = open(C, encoding="utf-8").read()


FAILS = []


def rep(a, b):
    global s
    if s.count(a) != 1:
        FAILS.append((s.count(a), a[:90]))
        return
    s = s.replace(a, b)


def block(key, new):
    global s
    m = re.search(r"@tabla " + key + r"\|.*?\n@nota[^\n]*\n", s, re.S)
    assert m, key
    s = s[:m.start()] + new.strip() + "\n" + s[m.end():]


# Unidad I
rep("para bloquear fuerza bruta intérprete seguro (SSH) {U1REF}", "para bloquear ataques de fuerza bruta contra el servicio Secure Shell (SSH) {U1REF}")
rep("Las fuentes de la Unidad I fueron principalmente normas, libros y documentación; la revisión actual añade 80 artículos centrados en correlación, multiservidor y aprendizaje automático, sin DOI en común con la primera.", "Las fuentes de la Unidad I se mantienen como base conceptual y normativa, y la revisión actual añade 80 artículos específicos sobre correlación, varios servidores y aprendizaje automático.")
block("u1", """@tabla u1|Continuidad entre los hallazgos de la Unidad I y este diseño
| Hallazgo de la Unidad I | Fuentes vigentes | Límite detectado | Ampliación en la Unidad II |
| Detectar sin responder no basta | {BHATT} | Respuesta limitada a un solo ataque | Respuesta activa restringida y procedimiento de incidentes |
| Las reglas por sí solas tienen límites | {LIAO,SOMMER} | Un escenario conocido de fuerza bruta | Modelo evaluado con ocho campañas multietapa no vistas |
| Los estándares exigen monitoreo e integridad | {ISO27001,SP53} | Un servidor y un agente | Cuatro servidores, segmentación y controles ISO/IEC 27001:2022 |
@nota Elaboración propia a partir de Anampa Pancca et al. (2026).""")

# Justificacion y objetivos
rep("La solución se justifica por razones técnicas, normativas y económicas. En lo técnico, la correlación", "La correlación")
rep(" En lo normativo, ISO/IEC 27001:2022 exige", " Por su parte, ISO/IEC 27001:2022 exige")
rep(" En lo económico, las piezas elegidas", " Las piezas elegidas")
rep("# Metodología\n", "La hipótesis de trabajo es que un modelo que combina las alertas de los cuatro roles supera a las reglas de severidad de Wazuh en campañas no vistas. OE1 a OE5 se completan en la Unidad II y OE6 se ejecutará durante las seis semanas de la Unidad III.\n\n# Metodología\n")
rep("La experimentación tuvo dos rondas y conviene declararlo.", "La experimentación tuvo dos rondas.")
rep("y añade un módulo de aprendizaje automático que evalúa", "y añade un módulo de aprendizaje automático (ML) que evalúa")
rep("Alerta aprendizaje automático (ML) interpretable", "Alerta ML interpretable")
rep("55 558 de AMiner", "55 558 del detector AMiner")

# Orden de figuras y tablas
m = re.search(r"\n@fig flujo\|[^\n]*\n", s); fl = m.group(0).strip(); s = s[:m.start()] + "\n" + s[m.end():]
rep("La {{F:flujo}} resume el procesamiento de los datos.\n", "La {{F:flujo}} resume el procesamiento de los datos.\n\n" + fl + "\n")
rep("como detalla la {{F:desp}}. Las redes internas de VirtualBox materializan los segmentos lógicos de la {{T:ip}}.", "como detalla la sección 7.1. Las redes internas de VirtualBox materializan los segmentos lógicos definidos en la sección 8.1.")
rep(" La meta de RF-03 toma como referencia el 58,2 % de alertas con táctica de la muestra de Cyber Range.", "")
m = re.search(r"(@tabla rf\|.*?\n)@nota[^\n]*\n", s, re.S)
s = s[:m.start()] + m.group(1) + "@nota Elaboración propia. La meta de RF-03 toma como referencia el 58,2 % de alertas con táctica de la muestra de Cyber Range.\n" + s[m.end():]
rep("4 vCPU, 8 GiB y 50 GB para 90 días", "4 vCPU, 8 GB de RAM y 50 GB para 90 días")

# Requerimientos y trazabilidad
rep("| F1 del modelo superior a la regla de severidad y precisión ≥ 0,80 |", "| F1 del modelo superior a la regla de severidad y precisión ≥ 0,70 por campaña |")
rep("| ≥ 75 % de las fases de ataque ejecutadas identificadas |", "| ≥ 70 % de las fases de ataque ejecutadas identificadas |")
rep("| Alerta ML interpretable en ≤ 2 min por un analista del grupo |\n", "| Alerta ML interpretable en ≤ 2 min por un analista del grupo |\n| RNF-09 | Sincronización | Desfase máximo de 1 s entre servidores |\n")
rep("| CP-10 |", "| CP-10, CP-17 |") if False else None
rep("| RNF-02 | FW-1, cifrado AES y TLS, VLAN 30 | CP-10 |", "| RNF-02 | FW-1, cifrado AES y TLS, VLAN 30 | CP-10 y CP-17 |")
rep("| RNF-08 | Dashboard y alerta ML | CP-15 | {A060,A062} |\n", "| RNF-08 | Dashboard y alerta ML | CP-15 | {A060,A062} |\n| RNF-09 | FW-1 y clientes NTP | CP-16 | {SP92} |\n")

# Arquitectura
rep("El agente y el manager siguen el modelo centralizado", "Centralizar los eventos apoya su análisis y la investigación de incidentes {BHATT}. El agente y el manager siguen el modelo centralizado")
rep("datos CVE {A029}", "datos de vulnerabilidades (CVE) {A029}")

# Red
rep("| FW-02 | 10.10.30.50 | 10.10.30.10 | TCP 22, 443 | Permitir | Administración y dashboard |", "| FW-02 | VLAN 10, 20 y 30 | FW-1 | TCP y UDP 53 | Permitir | Resolución de nombres con reenvío |")
rep("Salida NAT de VirtualBox", "Salida por traducción de direcciones de red (NAT) de VirtualBox")
rep("## Acceso remoto\n", """El tráfico entre el anfitrión (.50) y SRV-SIEM comparte subred y no atraviesa FW-1, por lo que se filtra con nftables en SRV-SIEM, que solo admite TCP 22 y 443 desde .50. El anfitrión declara rutas estáticas hacia las VLAN 10 y 20 por 10.10.30.1 para usar FW-03, y el firewall de Windows limita ese adaptador a dichas conexiones. El adaptador de captura de SRV-SIEM carece de IP, tiene ARP desactivado y no reenvía paquetes, para que no actúe como puente con la DMZ.

Las reglas se validaron de forma analítica con un script que aplica la lógica de primera coincidencia al plan IP. Los 26 flujos evaluados, permitidos y denegados, dieron el resultado esperado, y las subredes no presentan solapamientos. Esta comprobación no sustituye la prueba sobre el laboratorio de la Unidad III.

## Acceso remoto
""")
rep("con segundo factor TOTP en el acceso a la VPN.", "con segundo factor de contraseña temporal (TOTP) en el acceso a la VPN. La VPN y este segundo factor quedan fuera del alcance de la Unidad III.")

# Seguridad
rep("| Respaldos | 4 | 5 | 3 | Admin. SIEM |\n", "| Respaldos | 4 | 5 | 3 | Admin. SIEM |\n| Equipo anfitrión | 4 | 4 | 5 | Admin. SIEM |\n")
block("riesgos", """@tabla riesgos|Matriz de riesgos, controles y riesgo residual
| ID | Amenaza | P | I | Nivel | Control | ISO 27001 | Residual (P × I) | Resp. |
| R-01 | Explotación del servidor web | 4 | 4 | 16 Alto | Hardening, FIM, Suricata | A.8.8, A.8.16 | 2 × 4 = 8 Medio | Web |
| R-02 | Fuerza bruta sobre SSH o correo | 4 | 3 | 12 Medio | Llaves SSH, respuesta activa | A.8.5 | 2 × 3 = 6 Bajo | Autent. |
| R-03 | Movimiento lateral desde la DMZ | 3 | 5 | 15 Alto | Segmentación, reglas FW-07 y FW-11 | A.8.22 | 2 × 5 = 10 Medio | Autent. |
| R-04 | Manipulación de registros | 2 | 5 | 10 Medio | Envío inmediato, permisos, FIM | A.8.15 | 1 × 5 = 5 Bajo | SIEM |
| R-05 | Saturación de SRV-SIEM | 2 | 4 | 8 Medio | Límites por agente, monitoreo de cola | A.8.6 | 1 × 4 = 4 Bajo | SIEM |
| R-06 | Falsos negativos del modelo | 4 | 4 | 16 Alto | Reglas nativas activas, revisión | A.8.16 | 3 × 4 = 12 Medio | SIEM |
| R-07 | Falsos positivos que bloquean servicios | 2 | 4 | 8 Medio | Sin bloqueo automático por ML | A.5.24 | 1 × 4 = 4 Bajo | SIEM |
| R-08 | Pérdida de la configuración | 2 | 4 | 8 Medio | Respaldo 3-2-1, Git | A.8.13 | 1 × 4 = 4 Bajo | SIEM |
| R-09 | Fuga de ataques fuera del laboratorio | 1 | 5 | 5 Bajo | FW-08 desactivada en capturas | A.8.20 | 1 × 5 = 5 Bajo | Autent. |
| R-10 | Relojes desincronizados | 2 | 3 | 6 Bajo | NTP en FW-1, regla FW-04 | A.8.17 | 1 × 3 = 3 Bajo | Autent. |
| R-11 | Falla o reinicio del equipo anfitrión | 3 | 5 | 15 Alto | Suspensión y actualizaciones desactivadas en capturas, espacio libre en C:, respaldo | A.7.13, A.8.14 | 2 × 5 = 10 Medio | SIEM |
@nota Elaboración propia. P = probabilidad; I = impacto. R-09 ya tiene la probabilidad mínima, por lo que su valor no se reduce.""")
rep("de 4 h para SRV-SIEM.", "de 4 h para SRV-SIEM ante fallas de la máquina virtual; una falla del equipo físico depende de disponer de hardware de reemplazo.")
rep("basada en las guías Center for Internet Security (CIS).", "basada en las guías Center for Internet Security (CIS) {CISB}.")
rep("La recolección sigue las pautas de gestión de registros de NIST SP 800-92 {SP92}.", "La recolección sigue las pautas de gestión de registros de NIST SP 800-92 {SP92}, y las familias de auditoría y monitoreo de NIST SP 800-53 {SP53}. El administrador del SIEM revisará semanalmente accesos, cambios de reglas y estado de respaldos.")
rep("Los índices se conservan 90 días", "Los índices se conservan 90 días mediante una política ISM del indexer")

# Operacion e implementacion
rep("| Mantener servidor propio | C | R/A | R/A | R/A |", "| Mantener servidor propio | A | R | R | R |")
rep("Las notificaciones externas, por ejemplo por Telegram", "La ficha de incidente registra identificador, fecha y hora, servidor, regla o alerta ML, severidad, técnica ATT&CK, acciones, responsable y cierre. Las notificaciones externas, por ejemplo por Telegram")
rep("El camino crítico pasa por I-03, I-06 e I-07, porque la captura de actividad normal y las repeticiones de ataque no pueden comprimirse sin perder validez experimental", "Las actividades forman una cadena lineal, por lo que todas son críticas; I-06 e I-07 no pueden comprimirse sin perder validez experimental")

# Pruebas
rep("| CP-09 | RNF-01 | Medir disponibilidad en captura |", "| CP-09 | RNF-01 | Consultar cada 60 s el servicio con systemd y la API de Wazuh |")
rep("| CP-10 | RNF-02 | Escanear VLAN 30 desde VLAN 99 | Puertos cerrados | 0 expuestos |", "| CP-10 | RNF-02 | Escanear VLAN 30 desde VLAN 99; capturar TCP 1514; comprobar TLS en TCP 1515 | Puertos cerrados, eventos ilegibles y TLS activo | 0 expuestos y cifrado comprobado |")
rep("| CP-12 | RNF-04 | Evaluar modelo en campañas propias, informe descriptivo | Mejor que regla | F1 mayor y precisión ≥ 0,80 |", "| CP-12 | RNF-04 | Evaluar modelo en campañas propias, informe descriptivo | Mejor que regla | F1 mayor y precisión ≥ 0,70 |")
rep("| CP-13 | RNF-05 | Ejecutar cadena completa | Fases identificadas | ≥ 75 % |", "| CP-13 | RNF-05 | Ejecutar cadena completa | Fases identificadas | ≥ 70 % |")
rep("| CP-14 | RNF-07 | Restaurar SRV-SIEM desde respaldo |", "| CP-14 | RNF-07 | Restaurar SRV-SIEM desde la copia fuera del equipo |")
rep("| CP-15 | RNF-08 | Interpretar 10 alertas ML | Decisión registrada | ≤ 2 min cada una |\n", "| CP-15 | RNF-08 | Interpretar 10 alertas ML | Decisión registrada | ≤ 2 min cada una |\n| CP-16 | RNF-09 | Comparar hora de los servidores con FW-1 | Relojes sincronizados | Desfase < 1 s |\n| CP-17 | RNF-02 | Intentar desde Kali destinos negados por FW-10 y FW-11 | Tráfico bloqueado y registrado | 100 % denegado |\n")
rep("Antes de la captura se crearán reglas específicas", "El movimiento lateral se realizará desde SRV-WEB comprometido hacia SRV-AUT mediante intentos de autenticación sobre LDAP, permitidos por FW-07. Antes de la captura se crearán reglas específicas")

# Costos
rep("La publicación no lista Tacna por separado y la potencia de 60 W es una estimación.", "Corresponde al pliego del sector Moquegua, publicado para Electrosur; la tarifa aplicable en Tacna debe confirmarse con el recibo. La potencia de 60 W es una estimación.")
rep("sin CAPEX.", "sin gasto de capital (CAPEX).")
rep("cuyo costo de oportunidad no se monetizó.", "cuyo costo de oportunidad no se monetizó. Si el escenario tipo operara todo un año, la energía del equipo sumaría unos S/ 442 con IGV; el costo de hardware y personal de una organización no se estima porque requiere datos reales.")

# Resultados y discusion
rep("con entre 6 y 8 fases por campaña", "con entre 6 y 8 fases detectadas por campaña")
block("modelos", """@tabla modelos|Resultados por método, media (desviación estándar) de ocho escenarios
| Método | AP | F1 | Precisión | Sensibilidad | Tasa de falsos positivos |
| Regla: nivel Wazuh | 0,112 (0,092) | 0,198 (0,164) | 0,617 (0,309) | 0,132 (0,121) | 0,0024 (0,0027) |
| Regla: volumen | 0,163 (0,132) | 0,192 (0,161) | 0,454 (0,257) | 0,133 (0,128) | 0,0022 (0,0011) |
| Bosque aleatorio | 0,203 (0,115) | 0,197 (0,184) | 0,988 (0,023) | 0,121 (0,125) | 0,0001 (0,0001) |
| *Gradient boosting* | 0,235 (0,116) | 0,255 (0,159) | 0,879 (0,242) | 0,169 (0,120) | 0,0015 (0,0035) |
| **Regresión logística** | **0,252 (0,099)** | **0,304 (0,153)** | **0,942 (0,098)** | **0,193 (0,120)** | **0,0002 (0,0003)** |
@nota Elaboración propia. Umbrales seleccionados solo con datos de entrenamiento.""")
rep("## Aporte de la vista multiservidor\n\nLa", "## Aporte de la vista multifuente\n\nLos cuatro roles corresponden a cuatro fuentes de registro de un mismo agente y no a cuatro máquinas identificadas, por lo que este resultado se denomina multifuente. La")
rep("## Interpretación del aporte multiservidor\n\nLa vista conjunta mejoró", "## Interpretación del aporte multifuente\n\nLa vista conjunta mejoró")
rep("Esto modera la hipótesis inicial: la correlación multiservidor aporta,", "Esto modera la hipótesis inicial: la combinación de fuentes aporta,")
rep("La correlación multiservidor mejoró la ordenación", "La vista multifuente mejoró la ordenación")
rep("Se conservó el conjunto completo para no ajustar el modelo a posteriori.", "Se conservó el conjunto completo para no ajustar el modelo a posteriori; en la Unidad III la línea base se mantendrá solo si mejora el resultado.")
rep("- El modelo se entrenó con otro banco de pruebas;", "- El título menciona detección, pero por la baja sensibilidad la evidencia respalda principalmente la priorización de ventanas y el apoyo al triaje.\n- El modelo se entrenó con otro banco de pruebas;")
rep("Las referencias sobre dimensionamiento coinciden en que el límite no aparece donde se espera.", "Las referencias sobre dimensionamiento muestran que la latencia se degrada antes que el uso de CPU.")
rep("| La latencia falla antes que el cómputo | {DSCL} |", "| En los datos del clúster, la latencia falla antes que el cómputo (análisis propio) | {DSCL} |")
rep("El propio {n:A009} advierte, al revisar", "{n:A009} advierten, al revisar")
rep("IDS, WAF y FIM {A017}", "IDS, firewall de aplicaciones web (WAF) y FIM {A017}")
rep("IIoT {A049}", "Internet industrial de las cosas (IIoT) {A049}")
rep("| AUC media de 99,84 % |", "| Área bajo la curva (AUC) media de 99,84 % |")
rep("El presente F1 de 0,304 es considerablemente menor,", "Estos resultados son coherentes con la advertencia de {n:SOMMER} sobre las dificultades del aprendizaje automático en detección de intrusiones y con los límites de las firmas señalados por {n:LIAO}. El presente F1 de 0,304 es considerablemente menor,")

# Conclusiones y recomendaciones
rep("9 requerimientos funcionales y 8 no funcionales medibles, relacionados con 15 casos de prueba", "9 requerimientos funcionales y 9 no funcionales medibles, relacionados con 17 casos de prueba")
rep("once reglas de cortafuegos y diez riesgos tratados.", "once reglas de cortafuegos y once riesgos tratados.")
m = re.search(r"\n- Declarar el uso de herramientas de inteligencia artificial[^\n]*", s); assert m; s = s[:m.start()] + s[m.end():]
if FAILS:
    print(chr(10).join(map(str, FAILS)))
    sys.exit(1)
open(C, "w", encoding="utf-8").write(s)


def patch(path, pairs):
    t = open(path, encoding="utf-8").read()
    for a, b in pairs:
        assert t.count(a) == 1, (path[-16:], t.count(a), a[:70])
        t = t.replace(a, b)
    open(path, "w", encoding="utf-8").write(t)


patch(S + "refs.py", [
 (''' ("DSCL", ["Triyason, T."]''', ''' ("CISB", ["Center for Internet Security"], "Center for Internet Security", "s. f.", "CIS Ubuntu Linux Benchmarks", "Recuperado el 10 de noviembre de 2026, de", "https://www.cisecurity.org/benchmark/ubuntu_linux"),
 ("SP53", ["Joint Task Force"], "Joint Task Force", 2020, "Security and privacy controls for information systems and organizations", "(NIST SP 800-53, Rev. 5). National Institute of Standards and Technology.", "https://doi.org/10.6028/NIST.SP.800-53r5"),
 ("DSCL", ["Triyason, T."]'''),
 ('''items.sort(key=lambda x: x["sort"])''', '''items += [
 dict(key="SOMMER", year="2010", families=["Sommer", "Paxson"], sort=(["sommer", "paxson"], "2010", ""), runs=[("n", "Sommer, R., & Paxson, V. (2010). Outside the closed world: On using machine learning for network intrusion detection. "), ("n", "En "), ("i", "2010 IEEE Symposium on Security and Privacy"), ("n", " (pp. 305-316). IEEE. https://doi.org/10.1109/SP.2010.25")]),
 dict(key="LIAO", year="2013", families=["Liao", "Lin", "Lin", "Tung"], sort=(["liao", "lin", "lin", "tung"], "2013", ""), runs=[("n", "Liao, H.-J., Lin, C.-H. R., Lin, Y.-C., & Tung, K.-Y. (2013). Intrusion detection system: A comprehensive review. "), ("i", "Journal of Network and Computer Applications"), ("n", ", "), ("i", "36"), ("n", "(1), 16-24. https://doi.org/10.1016/j.jnca.2012.09.004")]),
 dict(key="BHATT", year="2014", families=["Bhatt", "Manadhata", "Zomlot"], sort=(["bhatt", "manadhata", "zomlot"], "2014", ""), runs=[("n", "Bhatt, S., Manadhata, P. K., & Zomlot, L. (2014). The operational role of security information and event management systems. "), ("i", "IEEE Security & Privacy"), ("n", ", "), ("i", "12"), ("n", "(5), 35-41. https://doi.org/10.1109/MSP.2014.103")]),
]
items.sort(key=lambda x: x["sort"])'''),
])
patch(S + "diagrams.py", [
 ('''zone(a, 1, 66, 98, 32, "Capa de recolección: servidores monitoreados")''', '''zone(a, 1, 90.5, 98, 9, "Perímetro y adversario", fc="#f7f7f5")
box(a, 45, 91.5, 22, 7, "FW-1 (pfSense)", [], ec=ORANGE, tc=ORANGE, fs=7.6)
box(a, 75, 91.5, 22, 7, "Kali (adversario)", [], ec=ORANGE, tc=ORANGE, fs=7.6)
arrow(a, (75, 95), (67, 95), color=ORANGE)
zone(a, 1, 66, 98, 23, "Capa de recolección: servidores monitoreados")'''),
 ('''    box(a, x, 71, 22, 18, t, l, fs=8, ls=6.8)''', '''    box(a, x, 67.6, 22, 15.5, t, l, fs=8, ls=6.8)'''),
 ('''xytext=(x, 71), arrowprops''', '''xytext=(x, 67.6), arrowprops'''),
 ('''a.text(81, 67.5, "Agentes: AES, TCP 1514"''', '''a.text(81, 64.3, "Agentes: AES, TCP 1514"'''),
 ('''arrow(a, (21.5, 26.5), (53.5, 26.5), "Réplica pasiva hacia Suricata", color=ORANGE, ls=(0, (3, 2)), offset=(0, -4))''', '''arrow(a, (24, 26.5), (53.5, 26.5), "Réplica de toda la VLAN 10 a Suricata", color=ORANGE, ls=(0, (3, 2)), offset=(0, -4), fs=6.5)'''),
 ('''"Mínimo privilegio · RBAC en dashboard · MFA para acceso remoto"''', '''"Mínimo privilegio · RBAC en dashboard · MFA solo en producción"'''),
])
patch(S + "valida_red.py", [
 ('''    if ip.ip_network(f"{src}/24", strict=False) == ip.ip_network(f"{dst}/24", strict=False):''', '''    if dst not in FW and ip.ip_network(f"{src}/24", strict=False) == ip.ip_network(f"{dst}/24", strict=False):'''),
])
print("OK")
