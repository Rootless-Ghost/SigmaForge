#!/usr/bin/env python3
"""
SigmaForge CLI — Command-line Sigma rule generation, validation, and conversion.

Usage:
    python cli.py generate --title "My Rule" --logsource process_creation --level high
    python cli.py validate rule.yml
    python cli.py convert rule.yml --backend splunk
    python cli.py template suspicious_powershell
    python cli.py templates
    python cli.py logsources
"""

import argparse
import sys
import os
import yaml
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.sigma_engine import (
    SigmaRule, SigmaValidator, SIEMConverter,
    build_rule_from_template, RULE_TEMPLATES, LOG_SOURCES,
    MITRE_ATTACK_MAP, TACTIC_IDS,
)


# ── Colors ──────────────────────────────────
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"


def banner():
    print(f"""
{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════╗
║           Σ  SigmaForge CLI v1.0.0           ║
║     Vendor-Agnostic Sigma Rule Generator     ║
╚══════════════════════════════════════════════╝{Colors.RESET}
""")


def print_header(text):
    print(f"\n{Colors.BLUE}{Colors.BOLD}── {text} ──{Colors.RESET}")


def print_success(text):
    print(f"{Colors.GREEN}✓{Colors.RESET} {text}")


def print_error(text):
    print(f"{Colors.RED}✗{Colors.RESET} {text}")


def print_warning(text):
    print(f"{Colors.YELLOW}⚠{Colors.RESET} {text}")


def print_info(text):
    print(f"{Colors.CYAN}ℹ{Colors.RESET} {text}")


def print_rule(yaml_str):
    """Print YAML with syntax highlighting."""
    for line in yaml_str.split("\n"):
        if line.strip().startswith("#"):
            print(f"  {Colors.DIM}{line}{Colors.RESET}")
        elif ":" in line:
            key, _, val = line.partition(":")
            print(f"  {Colors.CYAN}{key}{Colors.RESET}:{Colors.WHITE}{val}{Colors.RESET}")
        elif line.strip().startswith("- "):
            print(f"  {Colors.YELLOW}{line}{Colors.RESET}")
        else:
            print(f"  {line}")


# ── Commands ────────────────────────────────

def cmd_generate(args):
    """Generate a Sigma rule from CLI arguments."""
    # Parse detection from CLI
    detection = {}
    if args.field:
        selection = {}
        for field_spec in args.field:
            parts = field_spec.split("=", 1)
            if len(parts) != 2:
                print_error(f"Invalid field format: {field_spec} (use field=value or field|modifier=value)")
                sys.exit(1)
            key, val = parts
            # Handle comma-separated values
            values = [v.strip() for v in val.split(",")]
            if len(values) == 1:
                try:
                    selection[key] = int(values[0])
                except ValueError:
                    selection[key] = values[0]
            else:
                selection[key] = values
        detection["selection"] = selection
    else:
        detection["selection"] = {"Image|endswith": "\\example.exe"}

    detection["condition"] = args.condition or "selection"

    # Parse MITRE techniques
    techniques = []
    if args.mitre:
        techniques = [t.strip() for t in args.mitre.split(",")]

    # Parse false positives
    fps = []
    if args.falsepositives:
        fps = [f.strip() for f in args.falsepositives.split(",")]

    rule = SigmaRule(
        title=args.title or "Untitled Rule",
        description=args.description or "",
        log_source_key=args.logsource or "process_creation",
        detection=detection,
        level=args.level or "medium",
        status=args.status or "experimental",
        author=args.author or "SigmaForge",
        mitre_techniques=techniques,
        falsepositives=fps,
    )

    rule_yaml = rule.to_yaml()

    print_header("Generated Sigma Rule")
    print_rule(rule_yaml)

    # Validate
    validation = SigmaValidator.validate(rule_yaml)
    print_header("Validation")
    if validation["valid"]:
        print_success("Rule is valid")
    else:
        print_error("Rule has errors")
    for err in validation["errors"]:
        print_error(err)
    for warn in validation["warnings"]:
        print_warning(warn)

    # Convert
    if args.backend:
        backends = [args.backend]
    else:
        backends = ["splunk", "elastic", "eql", "sentinel"]

    for backend in backends:
        print_header(f"Conversion: {backend.upper()}")
        try:
            if backend == "wazuh":
                output = SIEMConverter.convert(
                    rule_yaml, backend,
                    rule_id=args.rule_id, group_name=args.group_name,
                )
                print(output)
            elif backend in ("dac_json", "qradar"):
                print(SIEMConverter.convert(rule_yaml, backend))
            else:
                query = SIEMConverter.convert(rule_yaml, backend)
                print(f"  {Colors.WHITE}{query}{Colors.RESET}")
        except Exception as e:
            print_error(f"Conversion failed: {e}")

    # Save to file
    if args.output:
        with open(args.output, "w") as f:
            f.write(rule_yaml)
        print_success(f"Rule saved to: {args.output}")


def cmd_validate(args):
    """Validate a Sigma rule file."""
    if not os.path.exists(args.file):
        print_error(f"File not found: {args.file}")
        sys.exit(1)

    with open(args.file, "r") as f:
        rule_yaml = f.read()

    print_header(f"Validating: {args.file}")
    validation = SigmaValidator.validate(rule_yaml)

    if validation["valid"]:
        print_success("Rule is valid")
    else:
        print_error("Rule has errors")

    for err in validation["errors"]:
        print_error(err)
    for warn in validation["warnings"]:
        print_warning(warn)


def cmd_convert(args):
    """Convert a Sigma rule to SIEM query."""
    if not os.path.exists(args.file):
        print_error(f"File not found: {args.file}")
        sys.exit(1)

    with open(args.file, "r") as f:
        rule_yaml = f.read()

    backends = [args.backend] if args.backend else ["splunk", "elastic", "eql", "sentinel"]

    for backend in backends:
        print_header(f"Conversion: {backend.upper()}")
        try:
            if backend == "wazuh":
                output = SIEMConverter.convert(
                    rule_yaml, backend,
                    rule_id=args.rule_id, group_name=args.group_name,
                )
                print(output)
            elif backend in ("dac_json", "qradar"):
                print(SIEMConverter.convert(rule_yaml, backend))
            else:
                query = SIEMConverter.convert(rule_yaml, backend)
                print(f"  {Colors.WHITE}{query}{Colors.RESET}")
        except Exception as e:
            print_error(f"Conversion failed: {e}")


def cmd_template(args):
    """Generate a rule from a pre-built template."""
    try:
        rule = build_rule_from_template(args.name)
    except ValueError:
        print_error(f"Unknown template: {args.name}")
        print_info("Available templates:")
        for key in RULE_TEMPLATES:
            print(f"  {Colors.CYAN}{key}{Colors.RESET}")
        sys.exit(1)

    rule_yaml = rule.to_yaml()

    print_header(f"Template: {args.name}")
    print_rule(rule_yaml)

    # Convert
    for backend in ["splunk", "elastic", "eql", "sentinel"]:
        print_header(f"Conversion: {backend.upper()}")
        try:
            query = SIEMConverter.convert(rule_yaml, backend)
            print(f"  {Colors.WHITE}{query}{Colors.RESET}")
        except Exception as e:
            print_error(f"Conversion failed: {e}")

    if args.output:
        with open(args.output, "w") as f:
            f.write(rule_yaml)
        print_success(f"Rule saved to: {args.output}")


def cmd_templates(args):
    """List all available templates."""
    print_header("Available Templates")
    for key, tmpl in RULE_TEMPLATES.items():
        level_colors = {
            "critical": Colors.RED,
            "high": Colors.YELLOW,
            "medium": Colors.CYAN,
            "low": Colors.GREEN,
            "informational": Colors.BLUE,
        }
        lc = level_colors.get(tmpl["level"], Colors.WHITE)
        techniques = ", ".join(tmpl["mitre_techniques"])
        print(f"  {Colors.CYAN}{key:30s}{Colors.RESET}  {lc}[{tmpl['level']:13s}]{Colors.RESET}  {tmpl['name']}")
        print(f"  {' ':30s}  {Colors.DIM}ATT&CK: {techniques}{Colors.RESET}")
        print()


def cmd_logsources(args):
    """List available log sources."""
    print_header("Available Log Sources")
    for key, src in LOG_SOURCES.items():
        desc = src.get("description", key)
        fields = ", ".join(src.get("fields", [])[:5])
        more = len(src.get("fields", [])) - 5
        if more > 0:
            fields += f" (+{more} more)"
        print(f"  {Colors.CYAN}{key:25s}{Colors.RESET}  {desc}")
        print(f"  {' ':25s}  {Colors.DIM}Fields: {fields}{Colors.RESET}")
        print()


# ── Main ────────────────────────────────────

def main():
    banner()

    parser = argparse.ArgumentParser(
        description="SigmaForge CLI — Vendor-Agnostic Sigma Rule Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # generate
    gen_parser = subparsers.add_parser("generate", help="Generate a new Sigma rule")
    gen_parser.add_argument("--title", "-t", help="Rule title")
    gen_parser.add_argument("--description", "-d", help="Rule description")
    gen_parser.add_argument("--logsource", "-l", help="Log source key (e.g. process_creation)")
    gen_parser.add_argument("--level", choices=["informational", "low", "medium", "high", "critical"])
    gen_parser.add_argument("--status", choices=["experimental", "test", "stable"])
    gen_parser.add_argument("--author", help="Rule author")
    gen_parser.add_argument("--field", "-f", action="append",
                           help="Detection field (format: field|modifier=value). Can repeat.")
    gen_parser.add_argument("--condition", "-c", help="Detection condition (default: selection)")
    gen_parser.add_argument("--mitre", "-m", help="MITRE ATT&CK technique IDs (comma-separated)")
    gen_parser.add_argument("--falsepositives", help="False positives (comma-separated)")
    gen_parser.add_argument("--backend", "-b", choices=["splunk", "elastic", "eql", "sentinel", "wazuh", "qradar", "dac_json"])
    gen_parser.add_argument("--rule-id",    type=int, default=100001,      help="Wazuh rule ID (wazuh backend only)")
    gen_parser.add_argument("--group-name", default="sigma_rules",         help="Wazuh group name (wazuh backend only)")
    gen_parser.add_argument("--output", "-o", help="Output file path (.yml)")

    # validate
    val_parser = subparsers.add_parser("validate", help="Validate a Sigma rule file")
    val_parser.add_argument("file", help="Path to Sigma rule YAML file")

    # convert
    conv_parser = subparsers.add_parser("convert", help="Convert a Sigma rule to SIEM query")
    conv_parser.add_argument("file", help="Path to Sigma rule YAML file")
    conv_parser.add_argument("--backend", "-b", choices=["splunk", "elastic", "eql", "sentinel", "wazuh", "qradar", "dac_json"])
    conv_parser.add_argument("--rule-id",    type=int, default=100001,      help="Wazuh rule ID (wazuh backend only)")
    conv_parser.add_argument("--group-name", default="sigma_rules",         help="Wazuh group name (wazuh backend only)")

    # template
    tmpl_parser = subparsers.add_parser("template", help="Generate rule from template")
    tmpl_parser.add_argument("name", help="Template name")
    tmpl_parser.add_argument("--output", "-o", help="Output file path (.yml)")

    # templates
    subparsers.add_parser("templates", help="List available templates")

    # logsources
    subparsers.add_parser("logsources", help="List available log sources")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    commands = {
        "generate": cmd_generate,
        "validate": cmd_validate,
        "convert": cmd_convert,
        "template": cmd_template,
        "templates": cmd_templates,
        "logsources": cmd_logsources,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
