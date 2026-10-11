# Bitrix Full Path Disclosure: false positive fix

2026-10-05: scan 117 reported `bitrix_full_path_disclosure` on
`http://10.0.0.16:80/?USER_FIELD_MANAGER=1` with `matched word: error`.
The response was a regular application page served by uvicorn; `error` occurred
in CSS and JavaScript, without a disclosed Bitrix path.

The matcher now requires a PHP diagnostic followed on the same line by an
absolute Unix/Windows Bitrix PHP path and line number. HTTP status is not used
as proof, so PHP errors returned with HTTP 500 remain eligible. Requests, ID,
severity, tags and product/category bindings are unchanged; no index generation
is required. README and MANIFEST record this local change.

Validation: bundled Nuclei 3.11.1 accepted the updated template with `-validate`.
No template execution, network rescan, or test against a real Bitrix installation
was performed for this change. Existing stored findings were retained.
