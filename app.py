"""
SigmaForge - Flask Application
Web UI and API for Sigma rule generation, validation, and SIEM conversion.
"""

from flask import Flask, render_template, request, jsonify, send_file
import json
import os
import yaml
from datetime import datetime
import logging

from src.sigma_engine import (
    SigmaRule, SigmaValidator, SIEMConverter,
    build_rule_from_form, build_rule_from_template,
    RULE_TEMPLATES, LOG_SOURCES, MITRE_ATTACK_MAP, TACTIC_IDS,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24)

# Rule library storage
RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")
os.makedirs(RULES_DIR, exist_ok=True)


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
        data = request.get_json()
        rule = build_rule_from_form(data)
        rule_yaml = rule.to_yaml()

        # Validate
        validation = SigmaValidator.validate(rule_yaml)

        # Convert to all backends
        conversions = {}
        for backend in ["splunk", "elastic", "eql", "sentinel"]:
            try:
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
        app.logger.exception("Error while generating Sigma rule")
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
        for backend in ["splunk", "elastic", "eql", "sentinel"]:
            try:
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
        return jsonify({"success": False, "error": str(e)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.route("/api/validate", methods=["POST"])
def api_validate():
    """Validate a Sigma rule YAML string."""
    try:
        data = request.get_json()
        rule_yaml = data.get("rule_yaml", "")
        validation = SigmaValidator.validate(rule_yaml)
        return jsonify({"success": True, "validation": validation})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.route("/api/convert", methods=["POST"])
def api_convert():
    """Convert a Sigma rule to a specific SIEM backend."""
    try:
        data = request.get_json()
        rule_yaml = data.get("rule_yaml", "")
        backend = data.get("backend", "splunk")

        if backend not in ["splunk", "elastic", "eql", "sentinel"]:
            return jsonify({"success": False, "error": f"Unknown backend: {backend}"}), 400

        query = SIEMConverter.convert(rule_yaml, backend)
        return jsonify({"success": True, "query": query, "backend": backend})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


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

        filename = f"{safe_title}_{rule_id[:8]}.yml"
        filepath = os.path.join(RULES_DIR, filename)

        with open(filepath, "w") as f:
            f.write(rule_yaml)

        return jsonify({
            "success": True,
            "filename": filename,
            "message": f"Rule saved: {filename}",
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


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
        return jsonify({"success": False, "error": str(e)}), 400


@app.route("/api/library/load/<filename>", methods=["GET"])
def api_load_rule(filename):
    """Load a rule from the library."""
    try:
        # Build normalized absolute path and ensure it stays within RULES_DIR
        base_dir = os.path.abspath(RULES_DIR)
        requested_path = os.path.normpath(os.path.join(base_dir, filename))
        if not requested_path.startswith(base_dir + os.sep):
            return jsonify({"success": False, "error": "Invalid filename"}), 400

        filepath = requested_path
        if not os.path.exists(filepath):
            return jsonify({"success": False, "error": "Rule not found"}), 404

        with open(filepath, "r") as f:
            content = f.read()

        validation = SigmaValidator.validate(content)
        conversions = {}
        for backend in ["splunk", "elastic", "eql", "sentinel"]:
            try:
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
        logger.exception("Error loading rule '%s'", filename)
        return jsonify({"success": False, "error": "An internal error has occurred."}), 400


@app.route("/api/library/delete/<filename>", methods=["DELETE"])
def api_delete_rule(filename):
    """Delete a rule from the library."""
    try:
        base_dir = os.path.abspath(RULES_DIR)
        filepath = os.path.abspath(os.path.join(base_dir, filename))
        # Ensure the resolved path is within the rules directory to prevent path traversal
        if os.path.commonpath([base_dir, filepath]) != base_dir:
            return jsonify({"success": False, "error": "Invalid filename"}), 400
        if os.path.exists(filepath):
            os.remove(filepath)
            return jsonify({"success": True, "message": f"Deleted: {filename}"})
        return jsonify({"success": False, "error": "File not found"}), 404
    except Exception as e:
        logger.exception("Error deleting rule '%s'", filename)
        return jsonify({"success": False, "error": "An internal error has occurred."}), 400


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
        logger.exception("Error exporting rule library")
        return jsonify({"success": False, "error": "An internal error has occurred."}), 400


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
    app.run(debug=True, host="0.0.0.0", port=5000)
