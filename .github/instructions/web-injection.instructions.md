# Web Injection Signatures — Path-Specific Instructions

## Applies To
`angular/**`, `javascript/**`, `sqlinjection/**`, `css/**`, `ssi/**`,
`lfi-local-file-system-harvesting/**`, `uri/**`, `svg/**`, `httpheader/**`,
`email/**`, `json/**`, `soap/**`, `callback/**`, `parameter/**`,
`unix/**`, `python/**`, `java/**`, `applescript/**`, `custom/**`,
`meta/**`, `referer/**`, `ps/**`, `calc/**`, `ua/**`, `pf/**`,
`random/**`, `rbl/**`, `ascii/**`

## What These Are

Commodity injection signatures scraped from the internet since 2015.
Each category contains payload files for a specific injection vector.

## Categories

| Directory | Attack Type | Use Case |
|-----------|------------|----------|
| `angular/` | AngularJS template injection | `{{constructor.constructor('alert(1)')()}}` |
| `javascript/` | JS injection (7 files) | XSS payloads |
| `sqlinjection/` | SQL injection | `' OR 1=1 --` variants |
| `css/` | CSS injection | `expression()`, `url()` payloads |
| `ssi/` | Server-Side Include | `<!--#exec cmd="..."-->` |
| `lfi-*/` | Local File Inclusion | `../../etc/passwd` traversals |
| `uri/` | URI-based attacks (15 files) | Protocol handlers, data URIs |
| `svg/` | SVG injection (15 files) | Embedded JS in SVG |
| `httpheader/` | HTTP header injection (4 files) | CRLF injection |
| `email/` | Email header injection (2 files) | BCC injection |
| `json/` | JSON injection | Nested/malformed JSON |
| `soap/` | SOAP injection | XML-in-SOAP attacks |
| `callback/` | Callback URL injection (2 files) | SSRF via callbacks |
| `parameter/` | Parameter pollution | HPP payloads |
| `unix/` | Unix command injection (5 files) | `; cat /etc/passwd` |
| `python/` | Python code injection | `eval()` payloads |
| `java/` | Java injection | JNDI, deserialization |
| `applescript/` | AppleScript injection | macOS-specific |
| `random/` | Random fuzzing tokens (9 files) | Boundary values |
| `ascii/` | ASCII control characters | NULL, SOH, etc. |
| `calc/` | Formula injection (2 files) | CSV/spreadsheet |
| `ua/` | User-Agent fuzzing (3 files) | Long/malformed UAs |
| `meta/` | HTML meta tag injection (8 files) | Redirect, charset |

## Standalone Files

| File | Size | Description |
|------|------|-------------|
| `full-unicode.txt` | 5.3 MB | Complete Unicode fuzzing table |
| `no-experience-required-xss-*` | 133 KB | XSS signature collection |
| `xml-paste-from-gist.txt` | — | XML paste injection |

## Suggested Use

### Burp Intruder
Load category files as payloads in Burp Intruder for automated parameter testing.

### Custom Scripts
```bash
# Test a parameter against all SQL injection payloads
while IFS= read -r payload; do
  curl -s "https://target/search?q=${payload}" -o /dev/null -w "%{http_code}\n"
done < sqlinjection/sqli-payloads.txt
```

### Automated Fuzzing
Feed entire categories into fuzzing frameworks as seed dictionaries.

## These Are NOT Related to ICC

Web injection files are separate from the ICC/XML/graphics research.
They share this repo because the original "Commodity-Injection-Signatures"
project bundled all injection categories together.
