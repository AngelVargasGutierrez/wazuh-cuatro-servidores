"""Validacion analitica del plan IP y de las reglas FW-01 a FW-11 (primera coincidencia; no sustituye una prueba real)."""
import csv, ipaddress as ip, itertools, sys
sys.stdout.reconfigure(encoding="utf-8")
N = {"V10": "10.10.10.0/24", "V20": "10.10.20.0/24", "V30": "10.10.30.0/24", "V99": "10.10.99.0/24", "WAN": "10.0.2.0/24"}
NETS = {k: ip.ip_network(v) for k, v in N.items()}
H = {"WEB": "10.10.10.10", "COR": "10.10.10.20", "AUT": "10.10.20.10", "SIEM": "10.10.30.10", "ADM": "10.10.30.50", "KALI": "10.10.99.10", "FW10": "10.10.10.1", "FW20": "10.10.20.1", "FW30": "10.10.30.1", "FW99": "10.10.99.1", "NET": "93.184.216.34"}
FW = {"10.10.10.1", "10.10.20.1", "10.10.30.1", "10.10.99.1"}
ov = [(a, b) for (a, x), (b, y) in itertools.combinations(NETS.items(), 2) if x.overlaps(y)]
priv = all(n.is_private for n in NETS.values())


def inn(addr, spec):
    a = ip.ip_address(addr)
    if spec == "ANY":
        return True
    if spec == "FW":
        return addr in FW
    if spec == "WANOUT":
        return not any(a in n for k, n in NETS.items() if k != "WAN")
    return any(a in ip.ip_network(p) if "/" in p else addr == p for p in spec.split(","))


V = {"V10": N["V10"], "V20": N["V20"], "V30": N["V30"], "V99": N["V99"]}
L = lambda *k: ",".join(V[x] for x in k)
RULES = [
 ("FW-01", L("V10", "V20"), "10.10.30.10", {("tcp", 1514), ("tcp", 1515)}, "allow"),
 ("FW-02", L("V10", "V20", "V30"), "FW", {("udp", 53), ("tcp", 53)}, "allow"),
 ("FW-03", "10.10.30.50", L("V10", "V20"), {("tcp", 22)}, "allow"),
 ("FW-03", "10.10.30.50", "10.10.30.1", {("tcp", 443)}, "allow"),
 ("FW-04", L("V10", "V20", "V30", "V99"), "FW", {("udp", 123)}, "allow"),
 ("FW-05", L("V99"), "10.10.10.10", {("tcp", 22), ("tcp", 80), ("tcp", 443)}, "allow"),
 ("FW-06", L("V99"), "10.10.10.20", {("tcp", 25), ("tcp", 143), ("tcp", 993)}, "allow"),
 ("FW-07", L("V10"), "10.10.20.10", {("tcp", 389), ("tcp", 636), ("tcp", 53), ("udp", 53)}, "allow"),
 ("FW-08", L("V10", "V20", "V30"), "WANOUT", {("tcp", 80), ("tcp", 443)}, "temp_install"),
 ("FW-09", "10.10.10.10", "10.10.99.10", {("tcp", 4444), ("udp", 53)}, "temp_test"),
 ("FW-10", L("V99"), L("V20", "V30"), None, "deny"),
 ("FW-11", "ANY", "ANY", None, "deny"),
]


def ev(src, dst, proto, port, mode):
    if dst not in FW and ip.ip_network(f"{src}/24", strict=False) == ip.ip_network(f"{dst}/24", strict=False):
        return "no_cruza_fw", "-"
    for rid, s, d, ports, act in RULES:
        if inn(src, s) and inn(dst, d) and (ports is None or (proto, port) in ports):
            if act == "temp_install":
                if mode == "install":
                    return "allow", rid
                continue
            if act == "temp_test":
                if mode == "test":
                    return "allow", rid
                continue
            return act, rid
    return "deny", "implicita"


T = [
 ("Agente web a manager", "WEB", "SIEM", "tcp", 1514, "capture", "allow"), ("Registro agente correo", "COR", "SIEM", "tcp", 1515, "capture", "allow"), ("Agente aut a manager", "AUT", "SIEM", "tcp", 1514, "capture", "allow"),
 ("Web resuelve DNS en FW-1", "WEB", "FW10", "udp", 53, "capture", "allow"), ("SIEM resuelve DNS en FW-1", "SIEM", "FW30", "udp", 53, "install", "allow"), ("NTP desde web", "WEB", "FW10", "udp", 123, "capture", "allow"), ("NTP desde Kali", "KALI", "FW99", "udp", 123, "capture", "allow"),
 ("Consola de pfSense", "ADM", "FW30", "tcp", 443, "capture", "allow"), ("SSH admin a web", "ADM", "WEB", "tcp", 22, "capture", "allow"), ("SSH admin a aut", "ADM", "AUT", "tcp", 22, "capture", "allow"), ("Anfitrión a dashboard (misma subred)", "ADM", "SIEM", "tcp", 443, "capture", "no_cruza_fw"),
 ("CP-07 fuerza bruta SSH", "KALI", "WEB", "tcp", 22, "test", "allow"), ("CP-02 web", "KALI", "WEB", "tcp", 80, "test", "allow"), ("Correo de prueba", "KALI", "COR", "tcp", 143, "test", "allow"), ("LDAP web a aut", "WEB", "AUT", "tcp", 389, "test", "allow"), ("DNS web a aut", "WEB", "AUT", "tcp", 53, "test", "allow"),
 ("Parches web", "WEB", "NET", "tcp", 443, "install", "allow"), ("Parches bloqueados en captura", "WEB", "NET", "tcp", 443, "capture", "deny"), ("Shell inversa en prueba", "WEB", "KALI", "tcp", 4444, "test", "allow"), ("Shell inversa fuera de prueba", "WEB", "KALI", "tcp", 4444, "capture", "deny"), ("Exfiltración DNS en prueba", "WEB", "KALI", "udp", 53, "test", "allow"),
 ("CP-10 Kali a SIEM", "KALI", "SIEM", "tcp", 443, "test", "deny"), ("Kali a aut", "KALI", "AUT", "tcp", 389, "test", "deny"), ("Kali a Internet", "KALI", "NET", "tcp", 443, "test", "deny"), ("Web a SSH de SIEM", "WEB", "SIEM", "tcp", 22, "capture", "deny"), ("Web a dashboard", "WEB", "SIEM", "tcp", 443, "capture", "deny"), ("Aut a web (por defecto)", "AUT", "WEB", "tcp", 80, "capture", "deny"),
]
rows, ok = [], 0
for name, s, d, pr, po, mode, exp in T:
    res, rid = ev(H[s], H[d], pr, po, mode)
    good = res == exp
    ok += good
    rows.append(dict(Flujo=name, Origen=H[s], Destino=H[d], Puerto=f"{pr}/{po}", Fase=mode, Esperado=exp, Obtenido=res, Regla=rid, Resultado="OK" if good else "FALLA"))
with open(r"D:\ARTICULO_WAZUH\resultados\validacion_red.csv", "w", newline="", encoding="utf-8-sig") as f:
    w = csv.DictWriter(f, list(rows[0].keys()), delimiter=";"); w.writeheader(); w.writerows(rows)
print("solapamientos", ov, "privadas", priv, "flujos", len(T), "ok", ok)
for r in rows:
    if r["Resultado"] != "OK":
        print(r)
print("reglas usadas", sorted({r["Regla"] for r in rows}))
