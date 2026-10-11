#!/usr/bin/env python3
"""Build version checks and coverage notes from the reviewed vendor CVE snapshot.

Offline, deterministic generation. Review ranges and references in
security/vendor-cves.json before regeneration. No network probes or exploits.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "security/vendor-cves.json"


def scalar(value):
    return json.dumps(value, ensure_ascii=False)


def request_block(path, pattern, identity, constraints, http_only=False):
    # Require a version marker in THIS response: the engine retains named
    # extractors across requests, so an old version alone is insufficient.
    expression = " || ".join(
        "compare_versions(observed_version, " + ", ".join(scalar(c) for c in group) + ")"
        for group in constraints
    )
    if http_only:
        expression = 'starts_with(BaseURL, "http://") && (' + expression + ')'
    return "\n".join([
        "  - method: GET", "    path:", "      - " + scalar("{{BaseURL}}" + path),
        "    matchers-condition: and", "    matchers:",
        "      - type: status", "        status: [200]",
        "      - type: regex", "        regex:", "          - " + scalar(identity),
        "      - type: regex", "        regex:", "          - " + scalar(pattern),
        "      - type: dsl", "        name: potential-version-match", "        dsl:",
        "          - " + scalar("(" + expression + ")"),
        "    extractors:", "      - type: regex", "        name: observed_version",
        "        group: 1", "        regex:", "          - " + scalar(pattern),
    ])


def generate(entry):
    product = entry["product"]
    label = "MikroTik" if product == "mikrotik" else "GitLab"
    ports = "HTTP 80/443"  # these checks retrieve versions over HTTP(S)
    name = f'{label} {entry["id"]}: {entry["title"]} — потенциально по версии ({ports})'
    ranges = " или ".join(" и ".join(group) for group in entry["ranges"])
    description = (
        f'{entry["title"]}. Порт проверки: HTTP(S) 80/443, 8080/8443 или выбранный порт Web. '
        f'Затронутый сервис/порт: {entry["ports"]}. Условия: {entry["conditions"]}. '
        f'Диапазоны версии: {ranges}. '
        'GET получает опубликованную сервером версию и сравнивает её с бюллетенем. '
        'Совпадение означает потенциальный риск, эксплуатация и доступность затронутой функции не подтверждены. '
        'Если версия скрыта, результата не будет; это не означает, что устройство исправлено. '
        'Beta/rc версии автоматически не оцениваются.'
    )
    lines = [
        "id: " + entry["id"] + "-" + product + "-version", "", "info:",
        "  name: " + scalar(name), "  author: wscan", "  severity: " + entry["severity"],
        "  description: " + scalar(description), "  reference:",
        *["    - " + scalar(ref) for ref in entry["references"]],
        "  classification:", "    cve-id: " + entry["id"],
        "  metadata:", "    vendor: " + product, "    product: " + product,
        "    detection-method: version", "    confidence: potential",
        "    affected-ports: " + scalar(entry["ports"]),
        "    probe-ports: " + scalar("HTTP(S) 80/443, 8080/8443 или выбранный HTTP(S) порт"),
        "    reviewed-at: " + scalar("2026-10-05"),
        "  tags: cve," + product + ",safe", "", "http:",
    ]
    # Capture only stable release numbers. Explicit suffix boundaries exclude
    # prereleases, which the application's numeric comparator cannot evaluate.
    if product == "mikrotik":
        pattern = r'(?i)RouterOS\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\s|<|"|$)'
        for path in ("/", "/webfig/"):
            lines.append(request_block(path, pattern, r'(?i)RouterOS', entry["ranges"], entry["id"] == "CVE-2025-61481"))
    else:
        html_version = r'(?i)GitLab(?:\s+(?:Community|Enterprise)\s+Edition)?(?:\s+(?:CE|EE))?(?:\s|<[^>]{1,160}>){1,8}v?([0-9]+\.[0-9]+\.[0-9]+)(?:-(?:ee|ce))?(?:\s|<|"|$)'
        lines.append(request_block("/help", html_version, r'(?i)GitLab', entry["ranges"]))
        json_version = r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)(?:-(?:ee|ce))?"'
        for path in ("/api/v4/version", "/api/v4/metadata"):
            lines.append(request_block(path, json_version, r'"revision"\s*:\s*"[0-9a-fA-F]+"', entry["ranges"]))
    return "\n".join(lines) + "\n"


def main():
    data = json.loads(SNAPSHOT.read_text())
    notes = ["# MikroTik и GitLab: покрытие CVE", "", "Срез: " + data["checked_at"] + ".", "", data["scope"], "",
             "Протокольные проверки и наличие PoC: [аудит MikroTik](mikrotik-protocol-checks.md).", "",
             "## Как запускать", "",
             "В каталоге Web → CVE найдите `mikrotik-version` или `gitlab-version` (либо CVE ID). "
             "Выберите обнаруженный HTTP(S) сервис. Нестандартный порт берётся из выбранного сервиса/URL. "
             "Каждый шаблон подписан «потенциальный риск по версии»; в описании указаны порт GET-проверки и порт затронутой функции.", "",
             "Используются только GET без учётной записи. GitLab проверяется через /help, /api/v4/version, /api/v4/metadata; "
             "RouterOS — / и /webfig/. Если сервер требует входа или скрывает номер версии, CVE не определяется. "
             "Версия из публичного ответа может отличаться от реально установленного кода после backport исправлений. "
             "Редакция EE, архитектура, firewall, туннели и включённые функции требуют подтверждения. "
             "Beta/rc исключены, поскольку числовое сравнение движка не поддерживает prerelease.", "",
             "Существующие шаблоны с эксплуатацией остаются отдельными; новые проверки версии не отправляют их payload. "
             "Подбор паролей не добавляется в обычное сканирование.", "",
             "## Список", "", "| CVE | Продукт / что | Затронутые порты | Метод / условия |", "| --- | --- | --- | --- |"]
    count = 0
    for entry in data["entries"]:
        method = "Ручная проверка" if not entry["ranges"] else "GET, оценка версии"
        if entry["ranges"]:
            path = ROOT / "nuclei-templates/http/cves" / entry["id"].split("-")[1] / (entry["id"] + "-" + entry["product"] + "-version.yaml")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(generate(entry))
            count += 1
        link = f'[{entry["id"]}]({entry["references"][0]})'
        cells = [link, entry["product"] + ": " + entry["title"], entry["ports"], method + ". " + entry["conditions"]]
        notes.append("| " + " | ".join(cell.replace("|", "/").replace("\n", " ") for cell in cells) + " |")
    notes += ["", "## Ограничения списка", "",
              "CVE-2026-59108 и CVE-2026-67280 встречаются в changelog, но без опубликованного достаточного описания "
              "и точного диапазона не превращаются в автоматические проверки. Linux kernel и FastNetMon CVE с упоминанием MikroTik "
              "не относятся автоматически к RouterOS. Этот срез не является перечнем всех исторических CVE GitLab.", "",
              "Обновление: отредактировать security/vendor-cves.json по первичным источникам, затем "
              "`python3 tools/gen_vendor_cves.py` и `python3 tools/gen_categories.py` из library/.", ""]
    (ROOT / "security/vendor-cves.md").write_text("\n".join(notes))
    print(f"Generated {count} version checks; {len(data['entries']) - count} manual coverage entries")


if __name__ == "__main__":
    main()
