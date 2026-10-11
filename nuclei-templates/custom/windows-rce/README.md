# Windows remote checks

These templates check Windows network services. A remote check has to send
protocol requests; here, “check-only” means it does not authenticate, write
files, change account state, or attempt code execution.

| Template | Finding | Default use |
|---|---|---|
| `CVE-2017-0143.yaml` | MS17-010 / SMBv1 | Check-only. Reads the server response to an SMB transaction probe. |
| `CVE-2020-1472.yaml` | Zerologon / Netlogon | Check-only. Does not call `NetrServerPasswordSet` or reset the machine account password. |
| `../../network/cves/2020/CVE-2020-0796.yaml` | SMBGhost / SMBv3 | Check-only protocol negotiation; no exploit payload or write operation. |
| `../msf-scanner/msf-rdp-ms12-020-check.yaml` | MS12-020 / RDP | Metasploit scanner check; not the separate DoS module. |
| `CVE-2008-4250.yaml` | MS08-067 / Server service | Keep behind the exploit gate. The detection request itself can crash the target service. |

Do not classify a template as safe from its filename or CVE tag alone. Review
the request path and side effects. Templates tagged `exploit`, and NSE scripts
categorized `dos`, `exploit`, or `intrusive`, do not belong in the default
check-only selection unless their exact probe has been reviewed and explicitly
approved for that scan. Search the scanner catalog for `ad-check` to find the
curated check-only templates; the check probes still exchange network packets,
but do not change persistent target state.
