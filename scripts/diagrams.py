import os, sys, site
sys.path.append(site.getusersitepackages())
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle

OUT = r"D:\ARTICULO_WAZUH\figuras"
os.makedirs(OUT, exist_ok=True)
NAVY, INK, MUTE, BG, BLUE, ORANGE, GREEN, LINE = "#1f3a7a", "#1b1b1b", "#55534e", "#eef2f9", "#2a78d6", "#eb6834", "#1baf7a", "#8b93a3"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8.5})


def canvas(w, h):
    f, a = plt.subplots(figsize=(w, h))
    a.set_xlim(0, 100); a.set_ylim(0, 100); a.axis("off")
    return f, a


def box(a, x, y, w, h, title, lines=(), fc="white", ec=NAVY, tc=NAVY, fs=8.5, ls=7.2, lw=1.1, step=3.3):
    a.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.8", fc=fc, ec=ec, lw=lw))
    n = len(lines)
    top = y + h / 2 + (n * step) / 2 if n else y + h / 2
    a.text(x + w / 2, top if n else y + h / 2, title, ha="center", va="center", fontsize=fs, fontweight="bold", color=tc)
    for k, l in enumerate(lines):
        a.text(x + w / 2, top - (k + 1) * step, l, ha="center", va="center", fontsize=ls, color=INK)


def zone(a, x, y, w, h, label, fc=BG, right=False):
    a.add_patch(Rectangle((x, y), w, h, fc=fc, ec=LINE, lw=.8, ls=(0, (4, 3))))
    a.text(x + w - 1 if right else x + 1, y + h - 1.2, label, ha="right" if right else "left", va="top", fontsize=7.6, fontweight="bold", color=MUTE)


def arrow(a, p, q, label=None, color=NAVY, ls="-", offset=(0, 1.4), fs=6.9, rad=0):
    a.annotate("", xy=q, xytext=p, arrowprops=dict(arrowstyle="-|>", color=color, lw=1.15, ls=ls, connectionstyle=f"arc3,rad={rad}", shrinkA=0, shrinkB=0))
    if label:
        a.text((p[0] + q[0]) / 2 + offset[0], (p[1] + q[1]) / 2 + offset[1], label, ha="center", va="center", fontsize=fs, color=color, bbox=dict(fc="white", ec="none", pad=.6))


def save(f, n):
    f.savefig(os.path.join(OUT, n), dpi=220, bbox_inches="tight", facecolor="white", pad_inches=.04)
    plt.close(f)


# Arquitectura general
f, a = canvas(7.4, 4.5)
zone(a, 1, 90.5, 98, 9, "Perímetro y adversario", fc="#f7f7f5")
box(a, 45, 91.5, 22, 7, "FW-1 (pfSense)", [], ec=ORANGE, tc=ORANGE, fs=7.6)
box(a, 75, 91.5, 22, 7, "Kali (adversario)", [], ec=ORANGE, tc=ORANGE, fs=7.6)
arrow(a, (75, 95), (67, 95), color=ORANGE)
zone(a, 1, 66, 98, 23, "Capa de recolección: servidores monitoreados")
for x, t, l in [(3, "SRV-WEB (2)", ["Apache y web", "Agente · FIM"]), (27, "SRV-COR (3)", ["Postfix y Dovecot", "Agente · FIM"]), (51, "SRV-AUT (4)", ["OpenLDAP y DNS", "Agente · auditd"]), (75, "SRV-SIEM (1)", ["Agente 000", "Vigilancia local"])]:
    box(a, x, 67.6, 22, 15.5, t, l, fs=8, ls=6.8)
zone(a, 1, 25, 98, 38, "Capa de análisis: SRV-SIEM (1)", right=True)
box(a, 3, 42, 20, 14, "Suricata", ["IDS en modo pasivo", "eve.json"], fc="#fff6ef", ec=ORANGE, tc=ORANGE)
box(a, 27, 42, 21, 14, "Wazuh manager", ["Decodificadores y", "reglas · correlación"])
box(a, 52, 42, 21, 14, "Wazuh indexer", ["Índices de alertas", "retención 90 días"])
box(a, 77, 42, 20, 14, "Dashboard", ["Consulta y", "visualización"])
box(a, 27, 28, 46, 10, "Módulo de aprendizaje automático", ["Ventanas por servidor, puntuación y alerta"], fc="#effaf5", ec=GREEN, tc="#10734f")
for x in (14, 38, 62):
    a.annotate("", xy=(37.5 if x < 40 else (37.5 if x < 60 else 37.5), 56), xytext=(x, 67.6), arrowprops=dict(arrowstyle="-|>", color=NAVY, lw=1.1))
a.text(12, 58.5, "Agentes: AES, TCP 1514", fontsize=6.9, color=NAVY, ha="center")
arrow(a, (23, 49), (27, 49)); arrow(a, (48, 49), (52, 49)); arrow(a, (73, 49), (77, 49))
arrow(a, (34, 42), (34, 38), color="#10734f"); arrow(a, (42, 38), (42, 42), color="#10734f")
zone(a, 1, 2, 98, 20, "Capa de operación y respuesta", fc="#f7f7f5")
box(a, 69, 5, 28, 12, "Analista SOC", ["Triaje y decisión"], fc="white")
box(a, 36, 5, 29, 12, "Gestión de incidentes", ["Registro y seguimiento"], fc="white")
box(a, 3, 5, 29, 12, "Respuesta activa", ["Solo alta confianza"], fc="white", ec=ORANGE, tc=ORANGE)
arrow(a, (87, 42), (87, 17), color=MUTE); arrow(a, (69, 11), (65, 11)); arrow(a, (36, 11), (32, 11))
save(f, "d_arquitectura.png")

# Topologia de red
f, a = canvas(7.4, 4.2)
box(a, 32, 80, 36, 14, "pfSense (FW-1)", ["10.10.x.1 en cada segmento", "Política de denegación por defecto"], fc="#fff6ef", ec=ORANGE, tc=ORANGE, ls=6.6)
box(a, 76, 81, 23, 12, "WAN (NAT)", ["Solo instalación y parches"], ec=LINE, tc=MUTE, fs=7.6, ls=6)
a.plot([68, 76], [87, 87], color=LINE, lw=1)
Z = [(1, "VLAN 10: DMZ", "10.10.10.0/24", [("SRV-WEB", ".10"), ("SRV-COR", ".20")]), (26, "VLAN 20: Servicios", "10.10.20.0/24", [("SRV-AUT", ".10")]),
     (51, "VLAN 30: SOC", "10.10.30.0/24", [("Anfitrión", ".50"), ("SRV-SIEM", ".10")]), (76, "VLAN 99: Adversario", "10.10.99.0/24", [("Kali", ".10")])]
for x, l, n, hs in Z:
    zone(a, x, 8, 23, 56, l)
    a.text(x + 11.5, 56, n, ha="center", fontsize=7.6, color=INK)
    for k, (h, ip) in enumerate(hs):
        box(a, x + 2.5, 40 - k * 20, 18, 13, h, [ip], ec=ORANGE if h == "Kali" else NAVY, tc=ORANGE if h == "Kali" else NAVY, fs=7.6)
    a.plot([x + 11.5, x + 11.5, 50], [64, 72, 72], color=LINE, lw=1);
a.plot([50, 50], [72, 80], color=LINE, lw=1)
box(a, 3.5, 9.5, 18, 8.5, "NIC2, sin IP", [], ec=ORANGE, tc=ORANGE, fs=6.8)
arrow(a, (21.5, 13.5), (53.5, 22), "Réplica de la VLAN 10", color=ORANGE, ls=(0, (3, 2)), offset=(0, -3.2), fs=6.3)
a.text(62.5, 12, "Red solo anfitrión", ha="center", fontsize=6.6, color=MUTE)
save(f, "d_red.png")

# Seguridad
f, a = canvas(7.4, 4.4)
a.add_patch(Rectangle((2, 80), 96, 14, fc="#fff6ef", ec=ORANGE, lw=1.2))
a.text(50, 89.7, "Frontera FW-1: denegación por defecto y reglas FW-01 a FW-11", ha="center", va="center", fontsize=8.2, fontweight="bold", color=ORANGE)
a.text(50, 84, "ISO/IEC 27001:2022, A.8.20 · A.8.22", ha="center", va="center", fontsize=6.9, color=MUTE)
Z = [("VLAN 99: Adversario", "No confiable", ["Sin acceso a VLAN 20 y 30", "Solo superficie de prueba", "Red sin Internet en capturas"], ORANGE),
     ("VLAN 10: DMZ", "Confianza baja", ["Hardening CIS (A.8.9)", "FIM y agente (A.8.16)", "SSH: llaves y señuelo (A.8.5)", "Captura pasiva a Suricata"], BLUE),
     ("VLAN 20: Servicios", "Confianza media", ["Hardening CIS (A.8.9)", "auditd y agente", "Mínimo privilegio (A.5.15)", "Solo LDAP y DNS desde DMZ"], GREEN),
     ("VLAN 30: SOC", "Confianza alta", ["RBAC en dashboard (A.8.2)", "nftables en SRV-SIEM", "AES y TLS (A.8.24)", "Registros (A.8.15)", "NTP (A.8.17)", "Reglas y puntuación ML"], NAVY)]
for k, (t, tr, ls_, col) in enumerate(Z):
    x = 2 + k * 24.4
    a.add_patch(Rectangle((x, 26), 22.8, 50, fc="white", ec=col, lw=1.2))
    a.add_patch(Rectangle((x, 69), 22.8, 7, fc=col, ec=col))
    a.text(x + 11.4, 72.5, t, ha="center", va="center", color="white", fontsize=7.2, fontweight="bold")
    a.text(x + 11.4, 65.5, tr, ha="center", va="center", color=col, fontsize=7, fontstyle="italic")
    for i, l in enumerate(ls_):
        a.text(x + 11.4, 59.5 - i * 6.2, l, ha="center", va="center", fontsize=6.2, color=INK)
a.add_patch(Rectangle((2, 4), 96, 18, fc="#f7f7f5", ec=MUTE, lw=1.1))
a.text(50, 16.8, "Respuesta y recuperación: respaldo 3-2-1 (A.8.13) · RPO 24 h · RTO 4 h · incidentes (A.5.24 a A.5.29)", ha="center", va="center", fontsize=7, color=INK)
a.text(50, 9.6, "Equipo anfitrión fuera de las zonas: punto único de falla (R-11). MFA solo en producción.", ha="center", va="center", fontsize=6.8, color=MUTE)
save(f, "d_seguridad.png")

# Despliegue
f, a = canvas(7.4, 3.9)
zone(a, 1, 3, 98, 94, "Anfitrión: portátil i5-12500H, 23,6 GB de RAM, Windows 11, discos virtuales en D:", fc="#f7f7f5")
zone(a, 4, 12, 92, 72, "Oracle VirtualBox · redes internas por segmento")
V = [("FW-1", "pfSense CE", "1 vCPU · 1 GB", "16 GB", ORANGE), ("SRV-SIEM", "Ubuntu 24.04", "4 vCPU · 8 GB", "100 GB", NAVY), ("SRV-WEB", "Ubuntu 24.04", "2 vCPU · 2 GB", "30 GB", NAVY),
     ("SRV-COR", "Ubuntu 24.04", "2 vCPU · 2 GB", "30 GB", NAVY), ("SRV-AUT", "Ubuntu 24.04", "2 vCPU · 2 GB", "30 GB", NAVY), ("Kali", "Kali Linux", "2 vCPU · 2 GB", "40 GB", ORANGE)]
for k, (n, os_, c, d, col) in enumerate(V):
    box(a, 6 + k * 15, 30, 13.6, 42, n, [os_, c, d], ec=col, tc=col, fs=8, ls=6.2)
a.text(50, 20.5, "Total asignado: 13 vCPU sobre 16 hilos · 17 GB de RAM · 246 GB de disco", ha="center", fontsize=7.4, color=INK)
a.text(50, 7.5, "Estación de administración: adaptador solo anfitrión del equipo físico, 10.10.30.50", ha="center", fontsize=7.2, color=MUTE)
save(f, "d_despliegue.png")

# Flujo del modulo ML
f, a = canvas(7.4, 2.3)
S = [("alerts.json", ["Wazuh, 4 roles"]), ("Depuración", ["Suricata y", "correo"]), ("Ventanas", ["60 s por", "servidor"]), ("Línea base", ["120 min", "previos"]), ("Modelo", ["Umbral desde", "entrenamiento"]), ("Alerta ML", ["Regla propia", "Triaje humano"])]
for k, (t, l) in enumerate(S):
    box(a, 1 + k * 16.7, 15, 14.3, 70, t, l, ec=GREEN if k in (3, 4) else NAVY, tc="#10734f" if k in (3, 4) else NAVY, fs=7, ls=6.2, step=13)
    if k < 5:
        arrow(a, (15.3 + k * 16.7, 50), (17.7 + k * 16.7, 50))
save(f, "d_flujo_ml.png")

f, a = canvas(7.4, 2.5)
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
save(f, "d_flujo_info.png")
print(sorted(os.listdir(OUT)))
