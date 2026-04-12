<div align="center">

# 🔷 SigmaForge

### Vendor-Agnostic Sigma Rule Generator

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Sigma](https://img.shields.io/badge/Sigma-Detection--as--Code-06b6d4?style=flat-square)](https://sigmahq.io)

A detection engineering tool for generating, validating, and converting Sigma rules to multiple SIEM query languages. Build vendor-agnostic detection rules with MITRE ATT&CK mapping and convert to **Splunk SPL**, **Elastic KQL**, **Elastic EQL**, **Microsoft Sentinel KQL**, **Wazuh XML**, **QRadar AQL**, and **Detection-as-Code JSON**.

[Features](#features) · [Screenshots](#screenshots) · [Quick Start](#quick-start) · [CLI Usage](#cli-usage) · [Web UI](#web-ui) · [Templates](#pre-built-templates)

</div>


## Overview

SigmaForge streamlines the detection rule authoring process by providing both a **dark-themed web interface** and a **CLI tool** for creating Sigma rules — the industry standard for vendor-agnostic SIEM detection. Write once, convert to any SIEM.

Part of the **Detection Engineering Toolkit** alongside [YaraForge](https://github.com/Rootless-Ghost/YaraForge) (YARA rules) and [SnortForge](https://github.com/Rootless-Ghost/SnortForge) (Snort IDS rules).

## Screenshots

### Rule Builder
*Build Sigma rules visually with MITRE ATT&CK mapping and detection logic*

![Rule Builder](screenshots/SigmaForge_Rule_Builder.png)

### Generated Output
*YAML output with Splunk SPL, Elastic KQL, EQL, Sentinel KQL, Wazuh XML, QRadar AQL, and DaC JSON conversions*

![Generated Output](screenshots/SigmaForge_Generated_output.png)

### Templates
*12 pre-built detection templates covering common attack techniques*

![Templates](screenshots/SigmaForge_Templates.png)

### Validator
*Paste any Sigma YAML for syntax checking and SIEM conversion*

![Validator](screenshots/SigmaForge_Validator.png)

### Rule Library
*Save, load, export, and manage generated rules*

![Rule Library](screenshots/SigmaForge_Rule_Library.png)

## Features

- **Sigma Rule Generator** — Visual rule builder with detection logic, field modifiers, and boolean conditions
- **SIEM Conversion** — Convert rules to Splunk SPL, Elastic/Lucene KQL, Elastic EQL, Microsoft Sentinel KQL, Wazuh XML, QRadar AQL, and Detection-as-Code JSON
- **MITRE ATT&CK Mapping** — Auto-tag rules with technique IDs and tactics (120+ techniques)
- **Rule Validator** — Syntax checking against the Sigma specification
- **Pre-built Templates** — 12 ready-to-use detection templates for common threats
- **Rule Library** — Save, load, export, and manage generated rules
- **CLI Interface** — Generate, validate, and convert rules from the command line
- **13 Log Sources** — Process creation, Windows Security, Sysmon, PowerShell, DNS, firewall, proxy, registry, network connections, file events, and Linux

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Rootless-Ghost/SigmaForge.git
cd SigmaForge

# Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt

# Run the web interface
python app.py
# Open http://localhost:5000
```

## Deployment

SigmaForge is designed for **local use** by individual analysts and detection engineers. By default the Flask development server binds to `0.0.0.0:5000` with no authentication.

**Do not expose SigmaForge on a public or shared network interface without adding authentication first.** If you need to make it accessible beyond localhost, place it behind a reverse proxy (e.g. nginx, Caddy) with HTTP Basic Auth or SSO, or restrict access via VPN/firewall ACL. The rule library endpoint allows reading and writing files on disk — treat it accordingly.

For strictly local use, consider changing the bind address in `app.py` to `127.0.0.1`:

```python
app.run(debug=debug_mode, host="127.0.0.1", port=5000)
```

## CLI Usage

```bash
# List available templates
python cli.py templates

# Generate from template
python cli.py template suspicious_powershell
python cli.py template mimikatz_execution --output mimikatz.yml

# Generate custom rule
python cli.py generate \
    --title "Suspicious CMD Execution" \
    --logsource process_creation \
    --level high \
    --field "Image|endswith=\\cmd.exe" \
    --field "ParentImage|endswith=\\excel.exe,\\winword.exe" \
    --mitre T1059.003 \
    --output suspicious_cmd.yml

# Validate a rule
python cli.py validate my_rule.yml

# Convert to specific SIEM
python cli.py convert my_rule.yml --backend splunk
python cli.py convert my_rule.yml --backend elastic
python cli.py convert my_rule.yml --backend eql
python cli.py convert my_rule.yml --backend sentinel

# List available log sources
python cli.py logsources
```

## Web UI

The Flask-based web interface provides four main sections:

- **Rule Builder** — Visual form with metadata, MITRE ATT&CK selector, detection logic builder, and live output with SIEM conversion tabs (Splunk SPL, Elastic KQL, Elastic EQL, Sentinel KQL, Wazuh XML, QRadar AQL, DaC JSON)
- **Templates** — Browse and load 12 pre-built detection templates covering common attack techniques
- **Validator** — Paste any Sigma YAML and validate against the specification, then convert to SIEM queries
- **Rule Library** — Save generated rules, load them back, export as JSON bundle

## Pre-built Templates

| Template | Level | MITRE ATT&CK | Description |
|----------|-------|---------------|-------------|
| Suspicious PowerShell | High | T1059.001 | Encoded commands, download cradles, AMSI bypass |
| Mimikatz Execution | Critical | T1003.001 | Credential dumping via Mimikatz |
| Scheduled Task Persistence | Medium | T1053.005 | Suspicious scheduled task creation |
| Brute Force Detection | Medium | T1110 | Multiple failed logon attempts |
| Event Log Clearing | High | T1070.001 | Windows event log cleared |
| Suspicious DNS Query | Medium | T1071.004 | Queries to known malicious TLDs |
| LOLBin Execution | Medium | T1218 | Certutil, mshta, rundll32, regsvr32 abuse |
| Port Scan Detection | Medium | T1046 | High volume denied firewall connections |
| Suspicious User Agent | Medium | T1071.001 | Known tool/malware user agents in proxy |
| Registry Persistence | Medium | T1547.001 | Run key modification |
| Non-Standard Port Connection | Low | T1095 | Outbound connections to suspicious ports |
| Linux Reverse Shell | Critical | T1059.004 | Bash, netcat, Python reverse shell patterns |

## Supported Log Sources

| Key | Description | Product |
|-----|-------------|---------|
| `process_creation` | Process Creation (Sysmon EID 1 / Security 4688) | Windows |
| `windows_security` | Windows Security Event Log | Windows |
| `sysmon` | Sysmon Operational Log | Windows |
| `powershell` | PowerShell Script Block / Module Logging | Windows |
| `powershell_classic` | Windows PowerShell (Classic) | Windows |
| `dns_query` | DNS Query Events (Sysmon EID 22) | Windows |
| `network_connection` | Network Connection (Sysmon EID 3) | Windows |
| `file_event` | File Creation/Modification (Sysmon EID 11) | Windows |
| `registry_event` | Registry Value Set (Sysmon EID 13) | Windows |
| `firewall` | Firewall logs (vendor-agnostic) | Any |
| `proxy` | Web proxy / HTTP logs | Any |
| `linux_process` | Linux Process Creation (auditd) | Linux |
| `linux_auth` | Linux Authentication Logs | Linux |

## Project Structure

```
SigmaForge/
├── app.py                  # Flask web application
├── cli.py                  # CLI interface
├── requirements.txt        # Python dependencies
├── src/
│   ├── __init__.py
│   └── sigma_engine.py     # Core engine (generator, validator, converter)
├── templates/
│   └── index.html          # Web UI template
├── static/
│   ├── css/style.css       # Dark theme stylesheet
│   └── js/app.js           # Frontend JavaScript
├── rules/                  # Saved rule library
├── SECURITY.md
├── LICENSE
└── README.md
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/generate` | POST | Generate rule from form data |
| `/api/template/<key>` | GET | Load pre-built template |
| `/api/validate` | POST | Validate Sigma YAML |
| `/api/convert` | POST | Convert to SIEM query |
| `/api/library/save` | POST | Save rule to library |
| `/api/library/list` | GET | List saved rules |
| `/api/library/load/<file>` | GET | Load rule from library |
| `/api/library/delete/<file>` | DELETE | Delete saved rule |
| `/api/library/export` | GET | Export all rules as JSON |
| `/api/log-sources` | GET | List available log sources |
| `/api/mitre` | GET | MITRE ATT&CK technique map |
| `/api/templates` | GET | List available templates |

## Related Tools

| Tool | Purpose | Link |
|------|---------|------|
| **YaraForge** | YARA rule generation for malware/file detection | [GitHub](https://github.com/Rootless-Ghost/YaraForge) |
| **SnortForge** | Snort IDS/IPS rule generation for network detection | [GitHub](https://github.com/Rootless-Ghost/SnortForge) |
| **SigmaForge** | Sigma rule generation for SIEM detection | This repo |
| **SIREN** | NIST 800-61 incident response report generator | [GitHub](https://github.com/Rootless-Ghost/SIREN) |

## Roadmap

### v2 — Released

**Wazuh XML Backend (Phase 1 — Complete)**
- Native Wazuh XML rule emitter added to `src/sigma_engine.py`
- Logsource → decoder mapping (`_DECODER_PARENT` table)
- MITRE ATT&CK tagging (`<mitre><id>` blocks)
- Severity level mapping (Sigma → Wazuh rule level)
- OR conditions → multiple `<rule>` elements
- NOT conditions → `negate="yes"` on `<field>` elements
- Validated end-to-end against live Wazuh 4.14.4 / Win11x01 agent (EventID 1102, T1070.001)

**Wazuh XML Backend (Phase 2 — Complete)**
- CLI wiring (`--backend wazuh` flag with `--rule-id` / `--group-name`)
- Flask UI wiring (Wazuh output tab with inline re-convert panel)
- `<if_sid>` parent map audit and remap per logsource/service (Security → 63108, Sysmon → 61600, System → 60010, Linux syslog → 1002)
- Decoder-scoped `WAZUH_FIELD_MAP` — Windows Security, Sysmon, catch-all, and Linux auth/audit/syslog sub-maps

**QRadar AQL & Detection-as-Code JSON (Complete)**
- QRadar AQL backend: full AQL query generation with logsource filtering, field mapping, wildcard/regex/exact-match handling, and multi-value `IN()` collapsing
- Detection-as-Code JSON backend: structured JSON export preserving full detection logic, MITRE technique IDs, and metadata for CI/CD and SOAR pipeline integration

**Additional Backends (Planned)**
- CrowdStrike Falcon Query Language (FQL)
- Microsoft Defender XDR Advanced Hunting (KQL / DeviceEvents schema)

### Future Considerations
- REST API mode for CI/CD and SOAR pipeline integration
- Rule performance hints (unbounded content matches, missing fast_pattern)
- Field mapping profiles (Windows default, MDE schema, Elastic ECS)
- Carbon Black (CBQL) backend
- Field normalization layer: Sigma → canonical schema → backend mapping (prerequisite for scaling additional backends; evaluate pySigma integration)


## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) for details.


<div align="center">

Built by [Rootless-Ghost](https://github.com/Rootless-Ghost) 

</div>
