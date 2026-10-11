#!/usr/bin/env python3
"""Generate categories.json for every check in the wscan library.

Service labels use token-boundary matching (so "sambar" ≠ "samba").
Output is the machine-readable source of truth the scanner loads at runtime.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from catalog_scope import exclusion_reason

ROOT = Path(__file__).resolve().parents[1]


def apply_product_rules(entries: dict[str, dict]) -> None:
    """Apply reviewed overrides without changing the version-1 index schema."""
    rules = json.loads((ROOT / "security/product-rules.json").read_text(encoding="utf-8"))
    for key, entry in entries.items():
        full_path = "nuclei-templates/" + key if entry["kind"] == "nuclei" else key
        for rule in rules["overrides"]:
            if full_path in rule.get("paths", []) or (
                rule.get("path_regex") and re.fullmatch(rule["path_regex"], full_path)
            ):
                entry.update(rule.get("category", {}))
        # Dictionary checks belong exclusively to the credential guessing type.
        if "Подбор учётных данных" in entry["types"]:
            entry["types"] = ["Подбор учётных данных"]

# Ordered: first match wins. Tokens match whole hyphen/underscore/path parts.
SERVICE_RULES: list[tuple[str, list[str]]] = [
    ("WinRM", ["winrm", "wsman"]),
    ("SMB", ["smb", "smb2", "samba", "cifs", "microsoft-ds"]),
    ("SSH", ["ssh", "ssh2"]),
    ("FTP", ["ftp", "tftp"]),
    ("RDP", ["rdp", "ms-wbt-server", "terminal-services"]),
    ("DNS", ["dns", "dnssec", "mdns"]),
    ("Почта", ["smtp", "imap", "pop3", "pop", "mail"]),
    ("Базы данных", [
        "mysql", "mssql", "ms-sql", "postgres", "postgresql", "pgsql",
        "redis", "mongo", "mongodb", "oracle", "cassandra", "couchdb",
        "memcached", "elasticsearch", "sql", "db2", "informix", "maxdb",
    ]),
    ("LDAP", ["ldap", "kerberos", "krb5", "krb"]),
    ("SNMP", ["snmp"]),
    ("VPN", ["ike", "ipsec", "openvpn", "pptp", "wireguard", "l2tp"]),
    ("RPC / Windows", ["msrpc", "rpc", "netbios", "nbstat", "nbtstat", "nbd", "dcerpc"]),
    ("VNC", ["vnc"]),
    ("Telnet", ["telnet", "rlogin", "rsh"]),
    ("TLS / SSL", ["ssl", "ssl2", "sslv2", "tls"]),
    ("Контейнеры", ["docker", "kubernetes", "kubelet", "k8s"]),
    ("Облако", ["aws", "azure", "gcp", "alibaba", "cloud"]),
    ("Промышленные / IoT", [
        "modbus", "bacnet", "profinet", "s7", "iec", "mqtt", "coap",
        "opc", "dnp3", "ethernetip",
    ]),
    ("Web", ["http", "https", "ajp", "websocket"]),
]

NSE_TYPE = {
    "auth": "Аутентификация",
    "broadcast": "Широковещательная разведка",
    "brute": "Подбор учётных данных",
    "default": "Стандартные проверки",
    "discovery": "Обнаружение",
    "dos": "Отказ в обслуживании",
    "exploit": "Эксплойты",
    "external": "Внешние источники",
    "fuzzer": "Fuzzing",
    "intrusive": "Интенсивные проверки",
    "malware": "Проверки на malware",
    "safe": "Безопасные проверки",
    "version": "Определение версий",
    "vuln": "Уязвимости",
    "info": "Информация",
}

IMPACT_STRONG = {
    "dos", "intrusive", "exploit", "brute", "bruteforce", "fuzzer", "fuzz",
    "fuzzing", "rce", "sqli", "ssti", "xxe", "deserialization", "race-condition",
    "upload", "xss", "ssrf", "malware", "creds-stuffing", "credential-stuffing",
}
IMPACT_ACTIVE = {"vuln", "cve", "auth-bypass", "auth", "credentials", "intrusion"}
IMPACT_DISCOVERY = {
    "discovery", "version", "tech", "panel", "panels", "detect", "detection",
    "fingerprint", "safe", "default",
}

# Fallback when no SERVICE_RULES token hits and the template's own path
# gives no hint (e.g. a product-named check under nuclei-templates/custom/):
# classify by which protocol block it actually uses.
PROTOCOL_SERVICE = {
    "http": "Web",
    "ssl": "TLS / SSL",
    "dns": "DNS",
}
PROTOCOL_RE = re.compile(r"(?m)^(http|tcp|network|dns|ssl|flow):")

PART_RE = re.compile(r"[^a-z0-9]+")
NSE_CAT_RE = re.compile(r"categories\s*=\s*\{([^}]*)\}", re.S)
NSE_CAT_ITEM_RE = re.compile(r"[\"']([^\"']+)[\"']")
NUCLEI_ID_RE = re.compile(r"(?m)^id:\s*[\"']?([^\"'\n]+)")
NUCLEI_TAGS_RE = re.compile(r"(?m)^(?:\s*)tags:\s*(.+)$")
NUCLEI_NAME_RE = re.compile(r"(?m)^(?:\s*)name:\s*[\"']?(.+?)[\"']?\s*$")


def parts(text: str) -> set[str]:
    return {p for p in PART_RE.split(text.lower()) if p}


def token_hit(bag: set[str], tok: str) -> bool:
    """Whole-part match only. Allows numbered variants (smb2, ssl3), never sambar≈samba."""
    if tok in bag:
        return True
    for p in bag:
        if p.startswith(tok) and p[len(tok) :].isdigit():
            return True
    return False


def match_service(*blobs: str) -> str:
    bag: set[str] = set()
    for b in blobs:
        bag |= parts(b)
    for title, tokens in SERVICE_RULES:
        for tok in tokens:
            if token_hit(bag, tok):
                return title
    return "Прочие сервисы"


def nse_categories(text: str) -> list[str]:
    m = NSE_CAT_RE.search(text)
    if not m:
        return []
    return NSE_CAT_ITEM_RE.findall(m.group(1))


def impact_from_tags(tags: list[str], path: str) -> str:
    set_ = {t.lower() for t in tags}
    if (
        path.startswith("dast/")
        or path.startswith("javascript/") and "exploit" in path
        or path.startswith(("http/default-logins/", "javascript/default-logins/", "network/default-login/", "http/credential-stuffing/"))
        or path == "http/vulnerabilities/wordpress/wp-xmlrpc-brute-force.yaml"
    ):
        return "Сильное воздействие"
    if set_ & IMPACT_STRONG:
        return "Сильное воздействие"
    if set_ & IMPACT_ACTIVE:
        return "Активные проверки"
    if set_ & IMPACT_DISCOVERY:
        return "Обнаружение"
    return "Активные проверки"



WEB_FILE_ACCESS_TYPE = "Path Traversal / LFI"
WEB_FILE_ACCESS_RE = re.compile(
    r"\b(?:(?:path|directory)[ -]+traversal|local[ -]+file[ -]+inclusion|"
    r"arbitrary[ -]+file[ -]+(?:read|reading))\b", re.I
)


def is_web_file_access(rel: str, name: str, tags: list[str]) -> bool:
    """Exact labels/phrases only; remote file access, not local runner audit."""
    return (
        bool(set(t.lower() for t in tags) & {"lfi", "traversal", "path-traversal", "directory-traversal"})
        or bool(WEB_FILE_ACCESS_RE.search(name))
        or bool(re.search(r"(?:^|[/_-])(?:lfi|(?:path|dir|directory)-traversal)(?:[./_-]|$)", rel, re.I))
    )


def nuclei_type(rel: str) -> str:
    p = rel.lower()
    mapping = [
        # Credential-guessing checks live under three different top-level
        # dirs depending on protocol (http/default-logins for web panels,
        # javascript/default-logins for SMB/LDAP/MySQL/SSH/VNC/Redis/
        # RabbitMQ/…, network/default-login for raw-TCP ones like FTP) —
        # unified into one label (same string NSE_TYPE already uses for its
        # "brute" category) so every credential-guessing check, regardless
        # of protocol or implementation, groups together under the TUI's
        # "by type" axis instead of being scattered across JavaScript/Сеть/
        # per-panel-type buckets. Must come before the generic http/*,
        # javascript/, network/ fallbacks below.
        ("http/credential-stuffing/", "Подбор учётных данных"),
        ("http/default-logins/", "Подбор учётных данных"),
        ("javascript/default-logins/", "Подбор учётных данных"),
        ("network/default-login/", "Подбор учётных данных"),
        ("http/vulnerabilities/wordpress/wp-xmlrpc-brute-force.yaml", "Подбор учётных данных"),
        ("http/cves/", "CVE"),
        ("http/vulnerabilities/", "Уязвимости"),
        ("http/misconfiguration/", "Неверная конфигурация"),
        ("http/exposures/", "Утечки"),
        ("http/exposed-panels/", "Открытые панели"),
        ("http/technologies/", "Технологии"),
        ("http/takeovers/", "Takeover"),
        ("http/fuzzing/", "Fuzzing"),
        ("dns/", "DNS"),
        ("ssl/", "TLS / SSL"),
        ("network/", "Сеть"),
        ("javascript/", "JavaScript"),
        ("code/", "Code"),
        ("cloud/", "Облако"),
        ("dast/", "DAST"),
        ("file/", "Файлы"),
        ("headless/", "Headless"),
        ("workflows/", "Workflows"),
    ]
    for prefix, label in mapping:
        if p.startswith(prefix):
            return label
    top = p.split("/", 1)[0]
    return top.upper() if top else "Прочее"


def classify_nse(path: Path) -> dict:
    rel = f"nmap/scripts/{path.name}"
    text = path.read_text(errors="ignore")
    cats = nse_categories(text)
    service = match_service(path.stem, " ".join(cats))
    # Prefer explicit smb*/samba* filename over generic "Прочие"
    stem = path.stem.lower()
    if stem.startswith(("smb-", "smb2-", "samba-")) or stem in {"smb", "smb2", "samba"}:
        service = "SMB"
    types = [NSE_TYPE.get(c, c) for c in cats] or ["Без категории"]
    if service == "Web" and "brute" not in cats and is_web_file_access(rel, "", []):
        types.append(WEB_FILE_ACCESS_TYPE)
    return {
        "path": rel,
        "kind": "nse",
        "service": service,
        "types": types,
        "nse_categories": cats,
        "impact": impact_from_tags(cats, rel),
        "product": {
            "smb": "SMB и Windows", "smb2": "SMB и Windows", "samba": "SMB и Windows",
            "http": "HTTP веб-сервисы", "https": "HTTP веб-сервисы",
        }.get(path.stem.split("-", 1)[0].lower(), path.stem.split("-", 1)[0]),
    }


def classify_nuclei(path: Path, root: Path) -> dict | None:
    rel = path.relative_to(root).as_posix()
    if rel.startswith("workflows/") or rel.startswith("profiles/") or rel.startswith("helpers/"):
        return None
    text = path.read_text(errors="ignore")
    if exclusion_reason(rel, text):
        return None
    if not NUCLEI_ID_RE.search(text):
        return None
    tags_m = NUCLEI_TAGS_RE.search(text)
    tags_raw = tags_m.group(1) if tags_m else ""
    tags = [t.strip().strip("[]\",'") for t in re.split(r"[\s,]+", tags_raw) if t.strip().strip("[]\",'")]
    name_m = NUCLEI_NAME_RE.search(text)
    name = name_m.group(1).strip() if name_m else path.stem

    # Path-based service first for nuclei top-level dirs
    if rel.startswith(("http/", "headless/", "dast/")):
        service = "Web"
    elif rel.startswith("ssl/"):
        service = "TLS / SSL"
    elif rel.startswith("dns/"):
        service = "DNS"
    elif rel.startswith("file/"):
        service = "Файлы"
    elif rel.startswith("cloud/"):
        service = "Облако"
    else:
        service = match_service(rel, path.stem, " ".join(tags), name)
        if service == "Прочие сервисы":
            m = PROTOCOL_RE.search(text)
            proto = m.group(1) if m else ""
            if proto in PROTOCOL_SERVICE:
                service = PROTOCOL_SERVICE[proto]

    if token_hit(parts(tags_raw), "winrm") or path.stem == "winrm-detect":
        service = "WinRM"

    # Filename overrides: smb-/samba- prefix (not "sambar") or path under /smb/
    stem = path.stem.lower()
    if (
        stem.startswith(("smb-", "smb2-", "samba-"))
        or stem in {"smb", "smb2", "samba"}
        or "/smb/" in rel.lower()
    ) and not rel.startswith(("http/", "headless/", "dast/")):
        service = "SMB"

    return {
        "path": rel,
        "kind": "nuclei",
        "service": service,
        "types": [nuclei_type(rel)] + (
            [WEB_FILE_ACCESS_TYPE] if service == "Web"
            and nuclei_type(rel) != "Подбор учётных данных"
            and is_web_file_access(rel, name, tags) else []
        ),
        "tags": tags[:12],
        "impact": impact_from_tags(tags, rel),
        "name": name,
    }


def main() -> int:
    entries: dict[str, dict] = {}
    for p in sorted((ROOT / "nmap" / "scripts").glob("*.nse")):
        e = classify_nse(p)
        entries[e["path"]] = e

    nuc_root = ROOT / "nuclei-templates"
    for p in sorted(nuc_root.rglob("*")):
        if p.suffix.lower() not in {".yaml", ".yml"} or not p.is_file():
            continue
        e = classify_nuclei(p, nuc_root)
        if e:
            entries[e["path"]] = e

    apply_product_rules(entries)
    services = Counter(e["service"] for e in entries.values())
    kinds = Counter(e["kind"] for e in entries.values())
    doc = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "counts": {
            "total": len(entries),
            "by_kind": dict(kinds),
            "by_service": dict(sorted(services.items(), key=lambda kv: (-kv[1], kv[0]))),
        },
        "entries": entries,
    }
    out = ROOT / "categories.json"
    out.write_text(json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(entries)} entries, {out.stat().st_size // 1024} KB)")
    print("by_service:")
    for k, v in doc["counts"]["by_service"].items():
        print(f"  {v:5d}  {k}")
    # sanity: SMB must include real smb scripts and not sambar
    smb = [k for k, e in entries.items() if e["service"] == "SMB"]
    assert any(k.endswith("smb-os-discovery.nse") for k in smb), smb[:5]
    assert not any("sambar" in k for k in smb), "sambar false positive"
    print(f"SMB entries: {len(smb)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
