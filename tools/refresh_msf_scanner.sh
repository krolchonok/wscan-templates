#!/usr/bin/env bash
# Refresh Metasploit → wscan templates and rebuild categories.json.
#
# New YAML under nuclei-templates/ is picked up by the catalog automatically
# (WalkDir). This script only regenerates the MSF-derived subset when a local
# Metasploit checkout is available — then commit the result into the library
# repo so clients get it via `wscan library update` without needing MSF.
#
# Coverage policy (least effort / no msfconsole):
#   - Tcp/Udp constant-probe scanners → codegen (this script)
#   - HTTP MSF scanners (~329) → use upstream nuclei-templates (already synced)
#   - SMB MSF scanners (~12) → use NSE (smb-vuln-ms17-010, smb-enum-*, …)
#   - login/brute/DoS/file-write → intentionally skipped
set -euo pipefail
cd "$(dirname "$0")/.."

MSF_ROOT="${MSF_ROOT:-/opt/metasploit-framework/embedded/framework}"
if [[ ! -d "$MSF_ROOT/modules/auxiliary/scanner" ]]; then
  echo "MSF not found at $MSF_ROOT — leaving custom/msf-scanner/ unchanged"
  echo "Install/checkout Metasploit or set MSF_ROOT, then re-run."
  exit 0
fi

python3 tools/gen_msf_scanner.py --msf-root "$MSF_ROOT"
python3 tools/gen_categories.py
echo "OK: custom/msf-scanner/ refreshed and categories.json rebuilt"
echo "Commit library changes, then clients pick them up with: wscan library update"
