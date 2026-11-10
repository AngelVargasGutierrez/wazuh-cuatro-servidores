"""Construye referencias APA 7 y textos de cita para los 80 articulos y las fuentes normativas."""
import json, os, re, unicodedata, html
from collections import defaultdict

M = r"D:\ARTICULO_WAZUH\metadata"
corpus = {r["id"]: r for r in json.load(open(os.path.join(M, "corpus_80.json"), encoding="utf-8"))}
cr = json.load(open(os.path.join(M, "crossref_80.json"), encoding="utf-8"))

KEEP = {"wazuh", "siem", "xdr", "soar", "soc", "socs", "apt", "apts", "ai", "ml", "xai", "mitre", "att&ck", "nist", "ids", "nids", "hids", "ips", "waf", "fim", "ssh", "rdp", "dos",
        "iot", "iiot", "llm", "llms", "nlp", "mttd", "mttr", "suricata", "snort", "telegram", "whatsapp", "python", "ansible", "fastapi", "ubuntu", "cis", "cve", "edr", "grafana", "graylog",
        "virustotal", "yara", "shuffle", "pfsense", "n8n", "thehive", "sysmon", "windows", "d3fend", "ueba", "maac", "mif", "congraph", "defendgraph", "zenguard", "kademlia", "markov", "hoeffding",
        "fintech", "ppdioo", "usakti", "gt-i2ti", "lms", "hidden", "indonesia", "sergipe", "azuay", "tangerang", "cimahi", "jombang", "sulawesi", "selatan", "diskominfo", "kota", "dinas", "instituto", "federal", "superior", "universitario", "tecnológico", "open", "jurnal", "system", "hdt", "cam-lds", "big", "data"}
UP = {"wazuh": "Wazuh", "mitre": "MITRE", "att&ck": "ATT&CK", "siem": "SIEM", "markov": "Markov", "hoeffding": "Hoeffding", "kademlia": "Kademlia", "python": "Python", "ansible": "Ansible",
      "telegram": "Telegram", "whatsapp": "WhatsApp", "suricata": "Suricata", "snort": "Snort", "ubuntu": "Ubuntu", "windows": "Windows", "grafana": "Grafana", "graylog": "Graylog",
      "virustotal": "VirusTotal", "yara": "Yara", "pfsense": "pfSense", "thehive": "TheHive", "sysmon": "Sysmon", "fintech": "FinTech", "n8n": "n8n", "fastapi": "FastAPI", "shuffle": "Shuffle"}
PROPER_ONLY = {"hidden": False, "big": False, "data": False, "open": False, "system": False, "federal": False, "superior": False}
PROPER_PHRASE = [("Hidden Markov", "Hidden Markov"), ("Open Jurnal System", "Open Jurnal System"), ("Instituto Federal de Sergipe", "Instituto Federal de Sergipe"),
                 ("Instituto Superior Universitario Tecnológico del Azuay", "Instituto Superior Universitario Tecnológico del Azuay"), ("Sulawesi Selatan", "Sulawesi Selatan"),
                 ("Kota Tangerang", "Kota Tangerang"), ("Nusa Tenggara", "Nusa Tenggara"), ("Diskominfo Cimahi", "Diskominfo Cimahi"), ("Universitas", "Universitas"),
                 ("Big Data", "big data"), ("Random Forest", "random forest")]


def fix_title(t):
    t = re.sub(r"</?[a-zA-Z]+>", "", " ".join(html.unescape(html.unescape(t)).split())).replace("aWazuh", "a Wazuh")
    words = t.split(" ")
    letters = [w for w in words if re.search(r"[A-Za-zА-Яа-я]", w)]
    allcaps = sum(1 for w in letters if w.upper() == w) / max(1, len(letters)) > 0.7
    out = []
    for i, w in enumerate(words):
        core = re.sub(r"^[^\w&]+|[^\w&]+$", "", w).lower()
        acr = re.sub(r"[^A-Za-z]", "", w)
        keep_case = (not allcaps and len(acr) >= 2 and acr.upper() == acr) or (not allcaps and re.search(r"[a-z][A-Z]", w))
        if core in UP:
            nw = w.lower().replace(core, UP[core]) if core in w.lower() else w
        elif allcaps and core in {"apis", "ids", "ips", "apt", "soc", "cve", "dos", "fim", "waf", "ai", "ml", "wazuh", "siem"}:
            nw = w
        elif keep_case:
            nw = w
        else:
            nw = w.lower()
        out.append(nw)
    s = " ".join(out)
    s = re.sub(r"(^|[:?!]\s+)(\W*)([a-záéíóúа-я])", lambda m: m.group(1) + m.group(2) + m.group(3).upper(), s)
    for a, b in PROPER_PHRASE:
        s = re.sub(re.escape(a), b, s, flags=re.I)
    for pa, re_ in [(r"\bai\b", "AI"), (r"aidriven", "AI-driven"), (r"\bllms\b", "LLMs"), (r"\bllm\b", "LLM"), (r"\bsocs\b", "SOCs"), (r"\bsoc\b", "SOC"), (r"\bsiem\b", "SIEM"),
                    (r"\bwazuh\b", "Wazuh"), (r"\bmitre\b", "MITRE"), (r"\batt&ck\b", "ATT&CK"), (r"serangan dos\b", "serangan DoS"), (r"\bcve\b", "CVE")]:
        s = re.sub(pa, re_, s, flags=re.I)
    return s


def initials(given):
    parts = re.split(r"[\s]+", re.sub(r"\(.*$", "", given).strip())
    res = []
    for p in parts:
        if not p:
            continue
        if p in ("de", "do", "da", "dos", "das", "del"):
            res.append(p)
            continue
        sub = [x for x in p.split("-") if x]
        res.append("-".join(x[0].upper() + "." for x in sub))
    return " ".join(res)


OVER = {
 "A039": [("Jumiaty", ""), ("Soewito", "Benfano")],
 "A043": [("Monteros", "Marcelo"), ("Chuqui Quille", "José Fabián"), ("Benitez-Cacao", "Nayeli"), ("Velez-Guerrero", "Pablo")],
 "A049": [("Hussein", "Marwan Alaa"), ("Hamza", "Ekhlas Kadhum")],
 "A077": [("Islam", "Mohammad Anwarul")],
 "A007": [("Sutisna", "Taviv"), ("Trifebriyanto", "Fajar Gilang"), ("Humayra", "Ratu Fayyaza Ayu"), ("Rahayu", "Maya")],
 "A023": [("Andika", "A."), ("Efendi", "R.")],
 "A035": [("Ridwan", "Muhammad Ridwan Na'im"), ("Kurniawan", "Yudi")],
 "A038": [("Farrel", "Farhan Ibnu"), ("Mardianto", "Is"), ("Qamar", "Adrian Sjamsul")],
 "A048": [("Nova", "Fitri"), ("Pratama", "Muhammad Dehan"), ("Prayama", "Deddy")],
 "A071": [("Bompally", "Santosh Datta")],
 "A080": [("Mbonu", "Ijeoma Stephanie"), ("Iwuanyanwu", "Uzoamaka Azuka"), ("Uzoka", "Esther"), ("Oluoha", "Oluchukwu Modesta")],
}
OVER.update({
 "A030": [("Rao", "Navaneet R."), ("Shetty", "Praneeth P."), ("Joshi", "Rishab K."), ("Sai Prathik", "R."), ("Swathi", "K.")],
 "A069": [("Ekundayo", "Foluke"), ("Atoyebi", "Iyabode"), ("Soyele", "Adesola"), ("Ogunwobi", "Emmanuel O.")],
 "A025": [("Koshova", "O. P."), ("Lysenko", "D. V."), ("Volkov", "S. I.")],
 "A029": [("Paes", "Tadeu Marcos Borges"), ("Mendonça", "Eudes Danilo")],
 "A072": [("Ogbole", "Jolly I."), ("Okoruwa", "Precious Osobhalenewie"), ("Fadayomi", "Oladapo"), ("Akeju", "Bisola"), ("Edivri", "Joseph"), ("Abolaji", "Toyosi O.")],
 "A008": [("Mohan", "S."), ("Pradeep", "G."), ("Madhuravel", "P."), ("Deepakumaar", "R."), ("Dhivya", "J.")],
})
for a_ in cr["A052"]["authors"]:
    if a_["family"] == "P":
        a_.update(family="Santosh Reddy", given="P.")
for a_ in cr["A064"]["authors"]:
    a_["family"] = a_["family"].replace("\xa0", "")
TITLE_OVER = {"A025": "Suchasni tekhnolohii monitorynhu merezhevoi bezpeky: Rol SIEM Wazuh u vyiavlenni ta reahuvanni na zahrozy [Tecnologías modernas de monitoreo de seguridad de red: El papel del SIEM Wazuh en la detección y respuesta a amenazas]."}
cr["A025"].update(container="Tavriiskyi naukovyi visnyk. Seriia: Tekhnichni nauky")
cr["A031"].update(volume="4", issue="502")
cr["A025"].update(issue="1")
cr["A030"].update(page="896-915")
cr["A080"].update(volume="3", issue="2", page="1000-1019")
cr["A078"].update(page="6768-6776")
cr["A039"].update(page="239-251")
cr["A052"].update(page="1121-1130")
TR = {
 "A041": "Preprint",
 "A023": "Simulación y análisis de la efectividad de la seguridad de red con un sistema de prevención de intrusiones basado en Wazuh",
 "A010": "Detección y mitigación de ataques a aplicaciones web con Suricata IPS, Wazuh SIEM y firewall",
 "A002": "Implementación del monitoreo y prevención de ataques de desfiguración con apuestas en línea mediante Wazuh",
 "A006": "DefendGraph: Sistema experto semántico para alertas Wazuh con MITRE D3FEND",
 "A022": "Implementación de un prototipo SIEM basado en Wazuh en un sitio web con pruebas de FIM y búsqueda de amenazas",
 "A017": "Implementación de una arquitectura de seguridad integrada de IDS, WAF y FIM basada en Wazuh en la plataforma Open Journal System conforme al NIST Cybersecurity Framework",
 "A016": "Diseño y prototipo de simulación de un sistema de respuesta activa basado en Wazuh para detectar y mitigar malware con inteligencia de amenazas",
 "A047": "Análisis del sistema SIEM con Wazuh en la Oficina de Comunicación, Informática, Estadística y Cifrado de Sulawesi del Sur",
 "A048": "Wazuh como gestión de eventos de registro y detección de vulnerabilidades en servidores frente a ataques DoS",
 "A019": "Automatización de la configuración de Wazuh integrado con VirusTotal mediante Ansible para detectar y proteger contra malware",
 "A020": "Detección y prevención de desfiguración web con apuestas en línea mediante Wazuh SIEM y Snort IDS basado en firmas",
 "A035": "Implementación y evaluación de un sistema de ciberseguridad basado en Wazuh, Shuffle y Yara en el centro de datos de Diskominfo de la ciudad de Tangerang con el método PPDIOO",
 "A034": "Implantación del sistema Wazuh en el Instituto Federal de Sergipe: Estrategias, desafíos y resultados en entornos educativos",
 "A007": "Implementación y análisis del sistema de seguridad Wazuh-Graylog en Diskominfo Cimahi",
}
cr["A008"].update(volume="5", issue="2", page="270-275")
cr["A004"].update(volume="11", issue="5", page="10138-10143")
cr["A077"].update(volume="24", issue="4", page="311-327", container="Issues in Information Systems")


def authors_of(i):
    if i in OVER:
        return [{"family": f, "given": g} for f, g in OVER[i]]
    c, r = cr[i], corpus[i]
    a = [x for x in (c.get("authors") or []) if x.get("family") and x["family"] not in ("-",)]
    bad = i in ("A043", "A039") or not a
    if bad:
        a = []
        for n in r["authors"]:
            p = n.split()
            a.append({"family": p[-1], "given": " ".join(p[:-1])})
    return a


def apa_auth(a):
    fmt = [f"{x['family']}, {initials(x['given'])}".rstrip(", ").strip() if x["given"] else x["family"] for x in a]
    if len(fmt) == 1:
        return fmt[0]
    if len(fmt) <= 20:
        return ", ".join(fmt[:-1]) + ", & " + fmt[-1]
    return ", ".join(fmt[:19]) + ", … " + fmt[-1]


def surname_key(a):
    return unicodedata.normalize("NFKD", a[0]["family"]).encode("ascii", "ignore").decode().lower()


items = []
for i in corpus:
    c, r = cr[i], corpus[i]
    a = authors_of(i)
    y = c.get("year") or r["year"]
    cont = html.unescape(c.get("container") or r.get("venue") or "")
    if cont.isupper():
        cont = cont.title()
    cont = cont.replace("Security And Privacy", "Security and Privacy").replace("SECURITY AND PRIVACY", "Security and Privacy")
    title = TITLE_OVER.get(i) or fix_title(c.get("title") or r["title"])
    title = title.replace("xAI-Derived", "xAI-derived").replace("Wazuh-grafana", "Wazuh-Grafana").replace("Wazuh-graylog", "Wazuh-Graylog")
    if i in TR:
        title = title.rstrip(".") + f" [{TR[i]}]"
    if not title.endswith((".", "?", "!")):
        title += "."
    vol = c.get("volume")
    iss = c.get("issue")
    pg = c.get("page")
    tail = []
    runs = [("n", f"{apa_auth(a)} ({y}). {title} "), ("i", cont)]
    if vol:
        runs += [("n", ", "), ("i", str(vol))]
        if iss:
            runs.append(("n", f"({iss})"))
    elif iss:
        runs.append(("n", f", ({iss})"))
    if pg:
        runs.append(("n", f", {pg}"))
    if i == "A061":
        runs.append(("n", ". Publicación anticipada en línea"))
    runs.append(("n", ". "))
    doi = r["doi"]
    runs.append(("n", doi))
    if c.get("type") == "proceedings-article" and i != "A005":
        pb = c.get("publisher") or ""
        pb = "SBC" if "Brasileira" in pb or "SBC" in pb else "ACM" if "Computing Machinery" in pb or pb.startswith("ACM") else "IEEE" if "IEEE" in pb else pb
        runs = [runs[0], ("n", "En "), ("i", cont), ("n", (f" (pp. {pg}). " if pg else ". ") + f"{pb}. "), ("n", doi)]
    if i == "A041":
        runs = [("n", f"{apa_auth(a)} ({y}). "), ("i", title.replace(" [Preprint]", "").rstrip(".")), ("n", " [Preprint]. Research Square. "), ("n", doi)]
    if i == "A005":
        runs = [runs[0], ("n", "En "), ("i", "International Conference on AI, Cybersecurity, and Next-Gen Computing (ICACNC 2026) Proceedings"), ("n", " (pp. 18-22). TechShield Publications. "), ("n", doi)]
    fam = [x["family"] for x in a]
    items.append(dict(key=i, year=y, families=fam, runs=runs, sort=([unicodedata.normalize("NFKD", z["family"]).encode("ascii", "ignore").decode().lower() for z in a], str(y), title)))

NORMS = [
 ("ISO27001", ["International Organization for Standardization"], "ISO", 2022, "Information security, cybersecurity and privacy protection: Information security management systems: Requirements", "(ISO/IEC 27001:2022).", "https://www.iso.org/standard/27001"),
 ("ISO27005", ["International Organization for Standardization"], "ISO", 2022.1, "Information security, cybersecurity and privacy protection: Guidance on managing information security risks", "(ISO/IEC 27005:2022).", "https://www.iso.org/standard/80585.html"),
 ("CSF", ["National Institute of Standards and Technology"], "National Institute of Standards and Technology", 2024, "The NIST Cybersecurity Framework (CSF) 2.0", "(NIST CSWP 29).", "https://doi.org/10.6028/NIST.CSWP.29"),
 ("SP61", ["Nelson, A.", "Rekhi, S.", "Souppaya, M.", "Scarfone, K."], "Nelson et al.", 2025, "Incident response recommendations and considerations for cybersecurity risk management: A CSF 2.0 community profile", "(NIST SP 800-61r3). National Institute of Standards and Technology.", "https://doi.org/10.6028/NIST.SP.800-61r3"),
 ("SP30", ["Joint Task Force Transformation Initiative"], "Joint Task Force Transformation Initiative", 2012, "Guide for conducting risk assessments", "(NIST SP 800-30r1). National Institute of Standards and Technology.", "https://doi.org/10.6028/NIST.SP.800-30r1"),
 ("SP92", ["Kent, K.", "Souppaya, M."], "Kent y Souppaya", 2006, "Guide to computer security log management", "(NIST SP 800-92). National Institute of Standards and Technology.", "https://doi.org/10.6028/NIST.SP.800-92"),
 ("RFC1918", ["Rekhter, Y.", "Moskowitz, B.", "Karrenberg, D.", "de Groot, G. J.", "Lear, E."], "Rekhter et al.", 1996, "Address allocation for private internets", "(RFC 1918). IETF.", "https://doi.org/10.17487/RFC1918"),
 ("ATTACK", ["MITRE Corporation"], "MITRE Corporation", "s. f.", "MITRE ATT&CK", "Recuperado el 10 de noviembre de 2026, de", "https://attack.mitre.org/"),
 ("WZQS", ["Wazuh, Inc."], "Wazuh, Inc.", "s. f.-a", "Quickstart: Wazuh documentation (v. 4.14)", "Recuperado el 10 de noviembre de 2026, de", "https://documentation.wazuh.com/current/quickstart.html"),
 ("WZCL", ["Wazuh, Inc."], "Wazuh, Inc.", "s. f.-b", "Wazuh server cluster: Wazuh documentation", "Recuperado el 10 de noviembre de 2026, de", "https://documentation.wazuh.com/current/user-manual/manager/wazuh-server-cluster.html"),
 ("DSADS", ["Landauer, M.", "Skopik, F.", "Wurzenberger, M."], "Landauer, Skopik y Wurzenberger", "2023-d", "AIT alert data set (versión 1) [Conjunto de datos]", "Zenodo.", "https://doi.org/10.5281/zenodo.8263181"),
 ("DSCR", ["Sherif, E."], "Sherif", "2026-d", "Task-specific dataset for structural leakage in host intrusion alert corpora: A grouped evaluation framework for ATT&CK-aligned cyber risk mapping [Conjunto de datos]", "Zenodo.", "https://doi.org/10.5281/zenodo.19691904"),
 ("OSI", ["Organismo Supervisor de la Inversión en Energía y Minería"], "Organismo Supervisor de la Inversión en Energía y Minería", 2026, "Pliego tarifario de Electrosur: Vigencia 4 de noviembre de 2026", "", "https://www.osinergmin.gob.pe/Tarifas/Electricidad/PliegoTarifario?Id=180000"),
 ("U1REF", ["Anampa Pancca, D. J.", "Vargas Gutiérrez, Á. J.", "Salas Jimenez, W. E.", "Huanca Merma, G. B."], "Anampa Pancca et al.", 2026, "Implementación de Wazuh: Detección de ataques y respuesta activa automatizada", "[Informe de proyecto no publicado]. Universidad Privada de Tacna.", ""),
 ("CISB", ["Center for Internet Security"], "Center for Internet Security", "s. f.", "CIS Ubuntu Linux Benchmarks", "Recuperado el 10 de noviembre de 2026, de", "https://www.cisecurity.org/benchmark/ubuntu_linux"),
 ("SP53", ["Joint Task Force"], "Joint Task Force", 2020, "Security and privacy controls for information systems and organizations", "(NIST SP 800-53, Rev. 5). National Institute of Standards and Technology.", "https://doi.org/10.6028/NIST.SP.800-53r5"),
 ("DSCL", ["Triyason, T."], "Triyason", 2026, "Dataset and scripts for timeliness fails before compute: Lessons for benchmarking distributed SIEM deployments (versión 2.0.0) [Conjunto de datos]", "Zenodo.", "https://doi.org/10.5281/zenodo.22763421"),
]
for key, authors, short, year, title, extra, url in NORMS:
    fam = authors
    ystr = str(int(year)) if isinstance(year, float) else str(year).replace("-d", "")
    au = authors[0] if len(authors) == 1 else ", ".join(authors[:-1]) + ", & " + authors[-1]
    if not au.endswith("."):
        au += "."
    runs = [("n", f"{au} ({ystr}). "), ("i", title), ("n", (f" {extra} {url}" if extra.startswith(("(", "[")) else f". {extra} {url}").replace("  ", " ").rstrip())]
    if key.startswith("DS"):
        runs = [("n", f"{au} ({ystr}). "), ("i", title), ("n", f". {extra} {url}")]
    items.append(dict(key=key, year=ystr, families=[short], runs=runs, norm=True, short=short,
                      sort=([unicodedata.normalize("NFKD", z.split(",")[0]).encode("ascii", "ignore").decode().lower() for z in (authors if len(authors) > 1 else [au.rstrip(".")])], ystr, title)))

items += [
 dict(key="SOMMER", year="2010", families=["Sommer", "Paxson"], sort=(["sommer", "paxson"], "2010", ""), runs=[("n", "Sommer, R., & Paxson, V. (2010). Outside the closed world: On using machine learning for network intrusion detection. "), ("n", "En "), ("i", "2010 IEEE Symposium on Security and Privacy"), ("n", " (pp. 305-316). IEEE. https://doi.org/10.1109/SP.2010.25")]),
 dict(key="LIAO", year="2013", families=["Liao", "Lin", "Lin", "Tung"], sort=(["liao", "lin", "lin", "tung"], "2013", ""), runs=[("n", "Liao, H.-J., Lin, C.-H. R., Lin, Y.-C., & Tung, K.-Y. (2013). Intrusion detection system: A comprehensive review. "), ("i", "Journal of Network and Computer Applications"), ("n", ", "), ("i", "36"), ("n", "(1), 16-24. https://doi.org/10.1016/j.jnca.2012.09.004")]),
 dict(key="BHATT", year="2014", families=["Bhatt", "Manadhata", "Zomlot"], sort=(["bhatt", "manadhata", "zomlot"], "2014", ""), runs=[("n", "Bhatt, S., Manadhata, P. K., & Zomlot, L. (2014). The operational role of security information and event management systems. "), ("i", "IEEE Security & Privacy"), ("n", ", "), ("i", "12"), ("n", "(5), 35-41. https://doi.org/10.1109/MSP.2014.103")]),
]
items.sort(key=lambda x: x["sort"])
for x_ in items:
    a0_ = x_["runs"][0][1]
    head_, sep_, tail_ = a0_.partition("). ")
    x_["runs"][0] = (x_["runs"][0][0], head_.replace(", & ", " y ") + sep_ + tail_)
    _nr = []
    for k_, b_ in x_["runs"]:
        m_ = re.search(r" (\(versión[^)]*\) )?\[Conjunto de datos\]$", b_) if k_ == "i" else None
        if m_:
            _nr += [("i", b_[:m_.start()]), ("n", b_[m_.start():])]
        else:
            _nr.append((k_, b_))
    x_["runs"] = _nr
    x_["runs"] = [x_["runs"][0]] + [(k_, re.sub(r"(,\s|pp\. )(\w*\d+)-(\w*\d+)", r"\1\2–\3", b_) if not b_.startswith("http") else b_) for k_, b_ in x_["runs"][1:]]

# Citas con desambiguacion a/b
def base_cite(x):
    if x.get("norm"):
        return x["short"]
    f = x["families"]
    if len(f) == 1:
        return f[0]
    if len(f) == 2:
        return f"{f[0]} y {f[1]}"
    return f"{f[0]} et al."


CITE_NAME = {"A045": "Landauer, Skopik, Frank et al.", "A077": "M. A. Islam", "A037": "M. R. Islam y Rafique"}
_bc = base_cite
base_cite = lambda x: CITE_NAME.get(x["key"]) or _bc(x)
groups = defaultdict(list)
for x in items:
    groups[(base_cite(x), str(x["year"]))].append(x)
for (b, y), g in groups.items():
    if len(g) > 1 and not all(str(y).startswith("s.") for _ in g):
        for k, x in enumerate(g):
            x["suffix"] = "abcdefgh"[k]
            x["runs"][0] = ("n", x["runs"][0][1].replace(f"({y})", f"({y}{x['suffix']})", 1))
CITE = {x["key"]: (base_cite(x), f"{x['year']}{x.get('suffix', '')}") for x in items}
if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(encoding="utf-8")
    print(len(items))
    for x in items[:12] + items[-3:]:
        print("".join(t for _, t in x["runs"])[:230])
    print({k: v for k, v in CITE.items() if v[1][-1:].isalpha() and not v[1].startswith("s.")})
    print(CITE["A039"], CITE["A043"], CITE["A049"], CITE["A077"], CITE["A080"], CITE["A025"], CITE["A052"], CITE["A008"])
