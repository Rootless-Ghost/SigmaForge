<div align="center">

# 🔷 SigmaForge

### Vendor-Agnostic Sigma Rule Generator

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Sigma](https://img.shields.io/badge/Sigma-Detection--as--Code-06b6d4?style=flat-square)](https://sigmahq.io)

A detection engineering tool for generating, validating, and converting Sigma rules to multiple SIEM query languages. Build vendor-agnostic detection rules with MITRE ATT&CK mapping and convert to **Splunk SPL**, **Elastic KQL**, **Elastic EQL**, and **Microsoft Sentinel KQL**.

[Features](#features) · [Quick Start](#quick-start) · [CLI Usage](#cli-usage) · [Web UI](#web-ui) · [Templates](#pre-built-templates)

</div>


## Overview

SigmaForge streamlines the detection rule authoring process by providing both a **dark-themed web interface** and a **CLI tool** for creating Sigma rules — the industry standard for vendor-agnostic SIEM detection. Write once, convert to any SIEM.

Part of the **Detection Engineering Toolkit** alongside [YaraForge](https://github.com/Rootless-Ghost/YaraForge) (YARA rules) and [SnortForge](https://github.com/Rootless-Ghost/SnortForge) (Snort IDS rules).

## Features

- **Sigma Rule Generator** — Visual rule builder with detection logic, field modifiers, and boolean conditions
- **SIEM Conversion** — Convert rules to Splunk SPL, Elastic/Lucene KQL, Elastic EQL, and Microsoft Sentinel KQL
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

- **Rule Builder** — Visual form with metadata, MITRE ATT&CK selector, detection logic builder, and live output with SIEM conversion tabs (Splunk SPL, Elastic KQL, Elastic EQL, Sentinel KQL)
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

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built by [Rootless-Ghost](https://github.com/Rootless-Ghost) 

</div>
