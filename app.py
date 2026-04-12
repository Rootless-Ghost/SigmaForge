"""
SigmaForge - Flask Application
Web UI and API for Sigma rule generation, validation, and SIEM conversion.
"""

from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
import json
import os
import re
import yaml
from datetime import datetime
import logging
import traceback

from src.sigma_engine import (
    SigmaRule, SigmaValidator, SIEMConverter,
    build_rule_from_form, build_rule_from_template,
    RULE_TEMPLATES, LOG_SOURCES, MITRE_ATTACK_MAP, TACTIC_IDS,
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24)

# Basic logging configuration
logging.basicConfig(level=logging.INFO)

# Rule library storage
RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")
os.makedirs(RULES_DIR, exist_ok=True)

# Input validation constants
_MAX_RULE_YAML_BYTES = 50 * 1024  # 50 KB hard limit on rule_yaml / request body
_SAFE_GROUP_RE = re.compile(r'^[A-Za-z0-9._-]{1,64}$')  # allowlist for Wazuh group names


def _safe_library_path(filename: str) -> str:
    """Sanitize filename and return safe path within RULES_DIR. Returns None if unsafe."""
    sanitized = secure_filename(filename)
    if not sanitized or not sanitized.endswith((".yml", ".yaml")):
        return None
    filepath = os.path.join(RULES_DIR, sanitized)
    # Prevent path traversal
    if not os.path.abspath(filepath).startswith(os.path.abspath(RULES_DIR)):
        return None
    return filepath


# ─────────────────────────────────────────────
# Web Routes
# ─────────────────────────────────────────────

@app.route("/")
def index():
    """Main page - rule builder."""
    return render_template(
        "index.html",
        log_sources=LOG_SOURCES,
        mitre_map=MITRE_ATTACK_MAP,
        tactic_ids=TACTIC_IDS,
        templates=RULE_TEMPLATES,
    )


# ─────────────────────────────────────────────
# API Endpoints
# ─────────────────────────────────────────────

@app.route("/api/generate", methods=["POST"])
def api_generate():
    """Generate a Sigma rule from form data."""
    try:
        if request.content_length and request.content_length > _MAX_RULE_YAML_BYTES:
            return jsonify({"success": False, "error": "Request payload exceeds 50 KB limit."}), 400
        data = request.get_json()
        rule = build_rule_from_form(data)
        rule_yaml = rule.to_yaml()

        # Validate
        validation = SigmaValidator.validate(rule_yaml)

        # Convert to all backends
        wazuh_rule_id    = max(1, min(999_999, int(data.get("rule_id", 100001))))
        wazuh_group_name = str(data.get("group_name", "sigma_rules"))
        if not _SAFE_GROUP_RE.match(wazuh_group_name):
            return jsonify({"success": False, "error": "group_name contains invalid characters (allowed: A-Z a-z 0-9 . _ -)"}), 400
        conversions = {}
        for backend in ["splunk", "elastic", "eql", "sentinel", "wazuh", "qradar", "dac_json"]:
            try:
                if backend == "wazuh":
                    conversions[backend] = SIEMConverter.convert(
                        rule_yaml, backend,
                        rule_id=wazuh_rule_id, group_name=wazuh_group_name,
                    )
                else:
                    conversions[backend] = SIEMConverter.convert(rule_yaml, backend)
            except Exception as e:
                conversions[backend] = f"Conversion error: {str(e)}"

        # Get MITRE info
        mitre_info = []
        for tech_id in rule.mitre_techniques:
            info = MITRE_ATTACK_MAP.get(tech_id)
            if info:
                mitre_info.append({
                    "id": tech_id,
                    "name": info["name"],
                    "tactic": info["tactic"],
                    "tactic_id": TACTIC_IDS.get(info["tactic"], ""),
                })

        return jsonify({
            "success": True,
            "rule_yaml": rule_yaml,
            "rule_json": rule.to_dict(),
            "validation": validation,
            "conversions": conversions,
            "mitre_info": mitre_info,
        })
    except Exception as e:
        # Log full exception details server-side, but return a generic error message to the client
        logging.exception("Error occurred while generating Sigma rule")
        return jsonify({
            "success": False,
            "error": "An internal error occurred while generating the rule."
        }), 400


@app.route("/api/template/<template_key>", methods=["GET"])
def api_template(template_key):
    """Load a pre-built rule template."""
    try:
        rule = build_rule_from_template(template_key)
        rule_yaml = rule.to_yaml()

        validation = SigmaValidator.validate(rule_yaml)
        conversions = {}
        for backend in ["splunk", "elastic", "eql", "sentinel", "wazuh", "qradar", "dac_json"]:
            try:
                if backend == "wazuh":
                    conversions[backend] = SIEMConverter.convert(
                        rule_yaml, backend, rule_id=100001, group_name="sigma_rules",
                    )
                else:
                    conversions[backend] = SIEMConverter.convert(rule_yaml, backend)
            except Exception as e:
                conversions[backend] = f"Conversion error: {str(e)}"

        mitre_info = []
        for tech_id in rule.mitre_techniques:
            info = MITRE_ATTACK_MAP.get(tech_id)
            if info:
                mitre_info.append({
                    "id": tech_id,
                    "name": info["name"],
                    "tactic": info["tactic"],
                    "tactic_id": TACTIC_IDS.get(info["tactic"], ""),
                })

        # Return template data for form population
        template = RULE_TEMPLATES[template_key]
        return jsonify({
            "success": True,
            "template": template,
            "rule_yaml": rule_yaml,
            "rule_json": rule.to_dict(),
            "validation": validation,
            "conversions": conversions,
            "mitre_info": mitre_info,
        })
    except ValueError as e:
        # Do not expose internal error details to the client
        logging.warning("ValueError in api_template for key %s: %s", template_key, e)
        return jsonify({"success": False, "error": "Template not found."}), 404
    except Exception as e:
        logging.exception("Unexpected error in api_template for key %s", template_key)
        return jsonify({"success": False, "error": "An internal error occurred while loading the template."}), 400


@app.route("/api/validate", methods=["POST"])
def api_validate():
    """Validate a Sigma rule YAML string."""
    try:
        data = request.get_json()
        rule_yaml = data.get("rule_yaml", "")
        validation = SigmaValidator.validate(rule_yaml)
        return jsonify({"success": True, "validation": validation})
    except Exception as e:
        logging.exception("Unexpected error in api_validate")
        return jsonify({"success": False, "error": "An internal error occurred while validating the rule."}), 400


@app.route("/api/convert", methods=["POST"])
def api_convert():
    """Convert a Sigma rule to a specific SIEM backend."""
    try:
        if request.content_length and request.content_length > _MAX_RULE_YAML_BYTES:
            return jsonify({"success": False, "error": "Request payload exceeds 50 KB limit."}), 400
        data = request.get_json()
        rule_yaml = data.get("rule_yaml", "")
        if len(rule_yaml) > _MAX_RULE_YAML_BYTES:
            return jsonify({"success": False, "error": "rule_yaml exceeds 50 KB limit."}), 400
        backend = data.get("backend", "splunk")

        if backend not in ["splunk", "elastic", "eql", "sentinel", "wazuh", "qradar", "dac_json"]:
            return jsonify({"success": False, "error": f"Unknown backend: {backend}"}), 400

        if backend == "wazuh":
            rule_id    = max(1, min(999_999, int(data.get("rule_id", 100001))))
            group_name = str(data.get("group_name", "sigma_rules"))
            if not _SAFE_GROUP_RE.match(group_name):
                return jsonify({"success": False, "error": "group_name contains invalid characters (allowed: A-Z a-z 0-9 . _ -)"}), 400
            query = SIEMConverter.convert(rule_yaml, backend,
                                          rule_id=rule_id, group_name=group_name)
        else:
            query = SIEMConverter.convert(rule_yaml, backend)
        return jsonify({"success": True, "query": query, "backend": backend})
    except Exception as e:
        logging.exception("Unexpected error in api_convert for backend %s", backend)
        return jsonify({"success": False, "error": "An internal error occurred while converting the rule."}), 400


@app.route("/api/library/save", methods=["POST"])
def api_save_rule():
    """Save a rule to the local rule library."""
    try:
        data = request.get_json()
        rule_yaml = data.get("rule_yaml", "")

        # Parse to get ID and title for filename
        rule_data = yaml.safe_load(rule_yaml)
        rule_id = rule_data.get("id", "unknown")
        title = rule_data.get("title", "untitled")
        safe_title = "".join(c if c.isalnum() or c in "-_ " else "" for c in title)
        safe_title = safe_title.replace(" ", "_").lower()[:50]

        filename = secure_filename(f"{safe_title}_{rule_id[:8]}.yml")
        filepath = _safe_library_path(filename)
        if not filepath:
            return jsonify({"success": False, "error": "Invalid filename generated"}), 400

        with open(filepath, "w") as f:
            f.write(rule_yaml)

        return jsonify({
            "success": True,
            "filename": filename,
            "message": f"Rule saved: {filename}",
        })
    except Exception as e:
        logging.exception("Unexpected error in api_save_rule")
        return jsonify({"success": False, "error": "An internal error occurred while saving the rule."}), 400


@app.route("/api/library/list", methods=["GET"])
def api_list_rules():
    """List all saved rules in the library."""
    try:
        rules = []
        for filename in sorted(os.listdir(RULES_DIR)):
            if filename.endswith((".yml", ".yaml")):
                filepath = os.path.join(RULES_DIR, filename)
                with open(filepath, "r") as f:
                    content = f.read()
                try:
                    rule_data = yaml.safe_load(content)
                    rules.append({
                        "filename": filename,
                        "title": rule_data.get("title", "Unknown"),
                        "level": rule_data.get("level", "unknown"),
                        "status": rule_data.get("status", "unknown"),
                        "id": rule_data.get("id", ""),
                        "description": rule_data.get("description", "")[:100],
                        "yaml": content,
                    })
                except yaml.YAMLError:
                    rules.append({
                        "filename": filename,
                        "title": filename,
                        "level": "unknown",
                        "status": "unknown",
                        "error": "Failed to parse YAML",
                    })
        return jsonify({"success": True, "rules": rules})
    except Exception as e:
        logging.exception("Unexpected error in api_list_rules")
        return jsonify({"success": False, "error": "An internal error occurred while listing the rules."}), 400


@app.route("/api/library/load/<filename>", methods=["GET"])
def api_load_rule(filename):
    """Load a rule from the library."""
    try:
        filepath = _safe_library_path(filename)
        if not filepath:
            return jsonify({"success": False, "error": "Invalid filename"}), 400
        if not os.path.exists(filepath):
            return jsonify({"success": False, "error": "Rule not found"}), 404

        with open(filepath, "r") as f:
            content = f.read()

        validation = SigmaValidator.validate(content)
        conversions = {}
        for backend in ["splunk", "elastic", "eql", "sentinel", "wazuh", "qradar", "dac_json"]:
            try:
                if backend == "wazuh":
                    conversions[backend] = SIEMConverter.convert(
                        content, backend, rule_id=100001, group_name="sigma_rules",
                    )
                else:
                    conversions[backend] = SIEMConverter.convert(content, backend)
            except Exception as e:
                conversions[backend] = f"Conversion error: {str(e)}"

        return jsonify({
            "success": True,
            "rule_yaml": content,
            "validation": validation,
            "conversions": conversions,
        })
    except Exception as e:
        logging.exception("Error loading rule from library")
        return jsonify({"success": False, "error": "An internal error occurred while loading the rule."}), 400


@app.route("/api/library/delete/<filename>", methods=["DELETE"])
def api_delete_rule(filename):
    """Delete a rule from the library."""
    try:
        filepath = _safe_library_path(filename)
        if not filepath:
            return jsonify({"success": False, "error": "Invalid filename"}), 400
        if os.path.exists(filepath):
            os.remove(filepath)
            return jsonify({"success": True, "message": f"Deleted: {filename}"})
        return jsonify({"success": False, "error": "File not found"}), 404
    except Exception as e:
        logging.exception("Error deleting rule from library")
        return jsonify({"success": False, "error": "An internal error occurred while deleting the rule."}), 400


@app.route("/api/library/export", methods=["GET"])
def api_export_library():
    """Export all rules as a JSON bundle."""
    try:
        rules = []
        for filename in sorted(os.listdir(RULES_DIR)):
            if filename.endswith((".yml", ".yaml")):
                filepath = os.path.join(RULES_DIR, filename)
                with open(filepath, "r") as f:
                    content = f.read()
                try:
                    rules.append(yaml.safe_load(content))
                except yaml.YAMLError:
                    pass

        return jsonify({
            "success": True,
            "export_date": datetime.now().isoformat(),
            "rule_count": len(rules),
            "rules": rules,
        })
    except Exception as e:
        logging.exception("Error exporting rule library")
        return jsonify({"success": False, "error": "An internal error occurred while exporting the library."}), 400


@app.route("/api/log-sources", methods=["GET"])
def api_log_sources():
    """Return available log sources and their fields."""
    return jsonify({"success": True, "log_sources": LOG_SOURCES})


@app.route("/api/mitre", methods=["GET"])
def api_mitre():
    """Return MITRE ATT&CK technique mapping."""
    return jsonify({
        "success": True,
        "techniques": MITRE_ATTACK_MAP,
        "tactics": TACTIC_IDS,
    })


@app.route("/api/templates", methods=["GET"])
def api_templates():
    """Return available rule templates."""
    templates_summary = {}
    for key, tmpl in RULE_TEMPLATES.items():
        templates_summary[key] = {
            "name": tmpl["name"],
            "description": tmpl["description"],
            "log_source": tmpl["log_source"],
            "level": tmpl["level"],
            "mitre_techniques": tmpl["mitre_techniques"],
        }
    return jsonify({"success": True, "templates": templates_summary})


if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
