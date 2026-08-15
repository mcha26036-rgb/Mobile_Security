import os
import json
import uuid
import base64
import io
import logging
import sqlite3
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from flask import (
    Flask,
    render_template_string,
    request,
    redirect,
    url_for,
    flash,
    send_file,
    session,
    jsonify,
)

from werkzeug.utils import secure_filename

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import random


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "dev-secret-key-change-in-production"
)

app.config["UPLOAD_FOLDER"] = "/tmp/uploads"
app.config["REPORTS_FOLDER"] = "/tmp/reports"

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["REPORTS_FOLDER"], exist_ok=True)

# ==================== APP CONFIG ====================
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'
app.config['REPORTS_FOLDER'] = '/tmp/reports'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)

# ==================== DATABASE ====================
DB_PATH = '/tmp/security_assessment.db'

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            title TEXT,
            target TEXT,
            date TEXT,
            prepared_by TEXT,
            report_version TEXT,
            methodology TEXT,
            executive_summary TEXT,
            created_at TEXT,
            target_domains TEXT,  -- JSON list
            html_content TEXT     -- Full HTML report
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT,
            finding_id TEXT,
            title TEXT,
            category TEXT,
            risk TEXT,
            priority TEXT,
            cvss_score REAL,
            cwe_id TEXT,
            owasp_category TEXT,
            methodology TEXT,
            source_tool TEXT,
            affected_component TEXT,
            issue_description TEXT,
            remediation TEXT,
            evidence TEXT,
            references TEXT,  -- JSON list
            timestamp TEXT,
            count INTEGER,
            status TEXT,
            assigned_to TEXT,
            due_date TEXT,
            targets TEXT,  -- JSON list (Pentest)
            impact TEXT,
            poc_text TEXT,
            poc_images TEXT, -- JSON list of base64 strings
            burp_suite_scan_id TEXT,
            burp_suite_issue_type TEXT,
            FOREIGN KEY(report_id) REFERENCES reports(id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ==================== BRAND ASSET ====================
@app.route('/logo.png')
def logo_asset():
    logo_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logo.png')
    if os.path.exists(logo_path):
        return send_file(logo_path, mimetype='image/png', max_age=86400)
    return ('', 404)


# ==================== HELPER FUNCTIONS ====================
def normalize_risk_level(risk):
    if risk is None:
        return "Informational"
    if isinstance(risk, str):
        value = risk.strip()
        if not value:
            return "Informational"
        lowered = value.lower()
        mapping = {
            "critical": "Critical",
            "crit": "Critical",
            "high": "High",
            "high risk": "High",
            "severity high": "High",
            "medium": "Medium",
            "med": "Medium",
            "moderate": "Medium",
            "low": "Low",
            "info": "Informational",
            "informational": "Informational",
            "information": "Informational",
            "informative": "Informational",
            "none": "Informational",
        }
        return mapping.get(lowered, value)
    return str(risk)

def _normalize_text(value):
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return str(value).strip().lower()
    return str(value).strip().lower().replace("\n", " ").replace("\t", " ")

def _normalize_priority(priority):
    if priority is None:
        return ""
    value = str(priority).strip().upper()
    if value.startswith("P") and value[1:].isdigit():
        return value
    return value

def deduplicate_findings(findings):
    if not findings:
        return []
    deduped = []
    seen = {}
    for finding in findings:
        title = _normalize_text(finding.get("title") or finding.get("name"))
        category = _normalize_text(finding.get("category"))
        risk = normalize_risk_level(finding.get("risk", "Informational"))
        methodology = _normalize_text(finding.get("methodology")).upper()
        description = _normalize_text(finding.get("issue_description") or finding.get("description"))
        component = _normalize_text(finding.get("affected_component") or finding.get("file_name") or finding.get("location"))
        cve = _normalize_text(finding.get("cve") or finding.get("cwe") or finding.get("id") or finding.get("finding_id"))
        key = (title, category, risk, component or description)
        if key not in seen:
            entry = dict(finding)
            entry["occurrence_count"] = 1
            entry["methodologies_seen"] = [methodology] if methodology else []
            entry["ids_seen"] = [cve] if cve else []
            deduped.append(entry)
            seen[key] = len(deduped) - 1
        else:
            idx = seen[key]
            deduped[idx]["occurrence_count"] = deduped[idx].get("occurrence_count", 1) + 1
            if methodology and methodology not in deduped[idx].get("methodologies_seen", []):
                deduped[idx]["methodologies_seen"] = deduped[idx].get("methodologies_seen", []) + [methodology]
            if cve and cve not in deduped[idx].get("ids_seen", []):
                deduped[idx]["ids_seen"] = deduped[idx].get("ids_seen", []) + [cve]
    return deduped

# ==================== SECURITY FRAMEWORK (without scoring) ====================
METHODOLOGY_COLORS = {
    "SAST": "#8b5cf6",
    "SCA": "#10b981",
    "DAST": "#3b82f6",
    "PENTEST": "#ff6b6b"
}
RISK_COLORS = {
    "Critical": "#ef4444",
    "High": "#f59e0b",
    "Medium": "#8b5cf6",
    "Low": "#3b82f6",
    "Informational": "#10b981"
}
PRIORITY_COLORS = {
    "P1": "#ef4444",
    "P2": "#f59e0b",
    "P3": "#8b5cf6"
}
OWASP_TOP10_2021 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)"
}
CWE_TOP25 = {
    "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    "CWE-20": "Improper Input Validation",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-125": "Out-of-bounds Read",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    "CWE-416": "Use After Free",
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-862": "Missing Authorization",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-287": "Improper Authentication",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-77": "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
    "CWE-269": "Improper Privilege Management"
}
CVSS_SEVERITY = {
    (0.0, 3.9): {"level": "Low", "color": "#3b82f6"},
    (4.0, 6.9): {"level": "Medium", "color": "#f59e0b"},
    (7.0, 8.9): {"level": "High", "color": "#ef4444"},
    (9.0, 10.0): {"level": "Critical", "color": "#7c2d12"}
}

class SecurityAssessmentFramework:
    def __init__(self):
        self.tool_mapping = {
            "SAST": ["SonarQube", "Checkmarx", "Fortify", "Veracode"],
            "SCA": ["Snyk", "OWASP Dependency-Check", "WhiteSource", "Black Duck"],
            "DAST": ["ZAP", "Burp Suite", "Acunetix", "Nessus"],
            "PENTEST": ["Burp Suite Professional", "Burp Suite Community", "Burp Suite Enterprise"]
        }
        self.default_tools = {
            "SAST": "SonarQube",
            "SCA": "Snyk",
            "DAST": "ZAP",
            "PENTEST": "Burp Suite Professional"
        }
        self.methodology_colors = METHODOLOGY_COLORS
        self.risk_levels = {
            "Critical": {"color": "#ef4444", "icon": "🔥", "timeline": "< 24 hours"},
            "High": {"color": "#f59e0b", "icon": "⚠️", "timeline": "< 72 hours"},
            "Medium": {"color": "#8b5cf6", "icon": "🔶", "timeline": "Next release cycle"},
            "Low": {"color": "#3b82f6", "icon": "🔷", "timeline": "Quarterly review"},
            "Informational": {"color": "#10b981", "icon": "ℹ️", "timeline": "Documentation"}
        }
        self.priority_mapping = {
            "Critical": "P1",
            "High": "P1",
            "Medium": "P2",
            "Low": "P3",
            "Informational": "P3"
        }
        self.severity_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Informational": 5}

    def get_severity_level(self, risk):
        return self.severity_order.get(normalize_risk_level(risk), 6)

    def calculate_cvss_score(self, finding):
        user_risk = finding.get("risk", "Low").lower()
        if "critical" in user_risk:
            av, ac, pr, ui, c, i, a = 0.85, 0.77, 0.27, 0.62, 0.56, 0.56, 0.56
        elif "high" in user_risk:
            av, ac, pr, ui, c, i, a = 0.62, 0.44, 0.62, 0.62, 0.56, 0.56, 0.22
        elif "medium" in user_risk:
            av, ac, pr, ui, c, i, a = 0.55, 0.44, 0.85, 0.85, 0.22, 0.22, 0.22
        else:
            av, ac, pr, ui, c, i, a = 0.2, 0.44, 0.85, 0.85, 0.0, 0.0, 0.0
        exploitability = 8.22 * av * ac * pr * ui
        impact = 1 - ((1 - c) * (1 - i) * (1 - a))
        base_score = 0 if impact <= 0 else min(10, (impact * exploitability))
        if "critical" in user_risk and base_score < 9.0:
            base_score = 9.0 + random.uniform(0.0, 1.0)
        elif "high" in user_risk and base_score < 7.0:
            base_score = 7.0 + random.uniform(0.0, 0.9)
        elif "medium" in user_risk and base_score < 4.0:
            base_score = 4.0 + random.uniform(0.0, 2.9)
        elif "low" in user_risk and base_score > 3.9:
            base_score = 3.9 - random.uniform(0.0, 1.0)
        base_score = max(0.0, min(10.0, base_score))
        return round(base_score, 1)

    def map_to_owasp_top10(self, finding):
        title = finding.get("title", "").lower()
        desc = finding.get("issue_description", "").lower()
        if any(x in title or x in desc for x in ["sql", "injection", "nosql"]):
            return "A03"
        elif any(x in title or x in desc for x in ["xss", "cross-site", "scripting"]):
            return "A03"
        elif any(x in title or x in desc for x in ["broken access", "authorization", "privilege"]):
            return "A01"
        elif any(x in title or x in desc for x in ["cryptographic", "encryption", "ssl", "tls"]):
            return "A02"
        elif any(x in title or x in desc for x in ["insecure design", "architecture"]):
            return "A04"
        elif any(x in title or x in desc for x in ["misconfiguration", "configuration"]):
            return "A05"
        elif any(x in title or x in desc for x in ["vulnerable component", "outdated", "dependency"]):
            return "A06"
        elif any(x in title or x in desc for x in ["authentication", "session", "password"]):
            return "A07"
        elif any(x in title or x in desc for x in ["integrity", "deserialization", "insecure deserialization"]):
            return "A08"
        elif any(x in title or x in desc for x in ["logging", "monitoring"]):
            return "A09"
        elif any(x in title or x in desc for x in ["ssrf", "server-side request"]):
            return "A10"
        return "A05"

    def map_to_cwe(self, finding):
        title = finding.get("title", "").lower()
        if "sql injection" in title:
            return "CWE-89"
        elif "xss" in title or "cross-site scripting" in title:
            return "CWE-79"
        elif "command injection" in title:
            return "CWE-78"
        elif "path traversal" in title:
            return "CWE-22"
        elif "csrf" in title:
            return "CWE-352"
        elif "hardcoded" in title or "credentials" in title:
            return "CWE-798"
        elif "insecure deserialization" in title:
            return "CWE-502"
        elif "ssrf" in title:
            return "CWE-918"
        elif "xxe" in title:
            return "CWE-611"
        return "CWE-20"

    def determine_risk_level(self, cvss_score):
        for (min_score, max_score), severity in CVSS_SEVERITY.items():
            if min_score <= cvss_score <= max_score:
                return severity["level"]
        return "Low"

    def generate_finding_id(self, tool_type, sequence):
        tool_code = {"SAST": "S", "SCA": "C", "DAST": "D", "PENTEST": "P"}.get(tool_type, "G")
        timestamp = datetime.now().strftime("%Y%m")
        return f"{tool_code}-{timestamp}-{sequence:04d}"

    def normalize_finding(self, raw_finding, tool_type, tool_name):
        cvss_score = self.calculate_cvss_score(raw_finding)
        user_risk = raw_finding.get("risk")
        risk_level = normalize_risk_level(user_risk) if user_risk else self.determine_risk_level(cvss_score)
        owasp_category = self.map_to_owasp_top10(raw_finding)
        cwe_id = self.map_to_cwe(raw_finding)
        finding_id = self.generate_finding_id(tool_type, raw_finding.get("sequence", 1))
        normalized = {
            "finding_id": finding_id,
            "title": raw_finding.get("title", "Untitled Finding"),
            "category": raw_finding.get("category", "General"),
            "risk": risk_level,
            "priority": self.priority_mapping.get(risk_level, "P3"),
            "cvss_score": cvss_score,
            "cwe_id": cwe_id,
            "owasp_category": owasp_category,
            "methodology": tool_type,
            "source_tool": tool_name,
            "source_tool_version": raw_finding.get("tool_version", "Unknown"),
            "file_name": raw_finding.get("file_name", ""),
            "line_number": raw_finding.get("line_number", ""),
            "module_name": raw_finding.get("module_name", ""),
            "module_version": raw_finding.get("module_version", ""),
            "vulnerability_name": raw_finding.get("vulnerability_name", ""),
            "affected_url": raw_finding.get("affected_url", ""),
            "affected_component": raw_finding.get("affected_component", "/"),
            "evidence": raw_finding.get("evidence", "Automated detection"),
            "issue_description": raw_finding.get("issue_description", raw_finding.get("description", "Potential security risk")),
            "remediation": raw_finding.get("remediation", raw_finding.get("solution", "Implement recommended security measures")),
            "validation_method": raw_finding.get("validation_method", "Automated"),
            "replication_steps": raw_finding.get("replication_steps", ["Refer to evidence for replication"]),
            "references": [
                f"OWASP Top 10 2021: {OWASP_TOP10_2021.get(owasp_category, owasp_category)}",
                f"CWE: {CWE_TOP25.get(cwe_id, cwe_id)}"
            ],
            "iso_controls": self.map_to_iso_controls(raw_finding),
            "timestamp": raw_finding.get("timestamp", datetime.now().isoformat()),
            "count": 1,
            "status": "Open",
            "assigned_to": None,
            "due_date": None
        }
        if raw_finding.get("cve"):
            normalized["cve"] = raw_finding["cve"]
            normalized["references"].append(f"CVE: {raw_finding['cve']}")
        if tool_type == "PENTEST":
            normalized["targets"] = raw_finding.get("targets", [])
            normalized["vulnerability_description"] = raw_finding.get("vulnerability_description", normalized["issue_description"])
            normalized["impact"] = raw_finding.get("impact", "")
            normalized["poc_text"] = raw_finding.get("poc_text", normalized["evidence"])
            normalized["poc_images"] = raw_finding.get("poc_images", [])
            normalized["burp_suite_scan_id"] = raw_finding.get("burp_suite_scan_id", "")
            normalized["burp_suite_issue_type"] = raw_finding.get("burp_suite_issue_type", "")
            normalized["burp_suite_severity"] = raw_finding.get("burp_suite_severity", risk_level)
            if raw_finding.get("poc_text"):
                normalized["evidence"] = raw_finding["poc_text"]
        if tool_type == "SAST":
            if raw_finding.get("file_name"):
                normalized["evidence"] = f"File: {raw_finding['file_name']}"
                if raw_finding.get("line_number"):
                    normalized["evidence"] += f" (Line {raw_finding['line_number']})"
                if raw_finding.get("code_snippet"):
                    normalized["evidence"] += f"\nCode: {raw_finding['code_snippet']}"
        elif tool_type == "SCA":
            if raw_finding.get("module_name"):
                normalized["evidence"] = f"Module: {raw_finding['module_name']}"
                if raw_finding.get("module_version"):
                    normalized["evidence"] += f" v{raw_finding['module_version']}"
                if raw_finding.get("vulnerability_name"):
                    normalized["evidence"] += f"\nVulnerability: {raw_finding['vulnerability_name']}"
        elif tool_type == "DAST":
            if raw_finding.get("affected_url"):
                normalized["evidence"] = f"URL: {raw_finding['affected_url']}"
        return normalized

    def map_to_iso_controls(self, finding):
        controls = ["A.12.6.1"]
        title = finding.get("title", "").lower()
        if "development" in title or "code" in title:
            controls.append("A.14.2.1")
        if "malware" in title:
            controls.append("A.12.2.1")
        if "software" in title or "install" in title:
            controls.append("A.12.6.2")
        if "network" in title:
            controls.append("A.13.1.1")
        if "transfer" in title or "data" in title:
            controls.append("A.13.2.1")
        return controls

# ==================== REPORT GENERATOR ====================
class SecurityReportGenerator:
    def __init__(self, report_data=None):
        self.report_data = report_data or {
            "title": "Comprehensive Security Assessment Report",
            "date": datetime.now().strftime("%Y-%m-%d"),
            "generated_by": "EAII Security Team",
            "prepared_by": "Security Analyst",
            "target": "Target System",
            "target_domains": ["portal", "auth", "app"],
            "report_version": "2.1",
            "methodology": "Full Assessment (SAST+SCA+DAST+PENTEST)",
            "scope": "Full application stack assessment",
            "findings": [],
            "executive_summary": "",
            "methodology_details": "",
            "compliance_mapping": {}
        }
        self.framework = SecurityAssessmentFramework()

    def generate_charts(self, findings):
        risk_chart = self.generate_risk_breakdown_chart(findings)
        coverage_chart = self.generate_methodology_coverage_chart(findings)
        chart_data = self.get_chartjs_data(findings)
        return risk_chart, coverage_chart, chart_data

    def generate_risk_breakdown_chart(self, findings):
        try:
            risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
            for finding in findings:
                risk = normalize_risk_level(finding.get("risk", "Informational"))
                if risk in risk_counts:
                    risk_counts[risk] += 1
            risks = ["Critical", "High", "Medium", "Low", "Informational"]
            counts = [risk_counts[r] for r in risks]
            colors = [RISK_COLORS[r] for r in risks]
            fig, ax = plt.subplots(figsize=(8, 5))
            bars = ax.bar(risks, counts, color=colors, edgecolor='white', linewidth=1.5)
            ax.set_title('Risk Level Distribution', fontsize=14, fontweight='bold', color='#0a1a3b')
            ax.set_xlabel('Risk Level', fontsize=12)
            ax.set_ylabel('Number of Findings', fontsize=12)
            ax.grid(True, alpha=0.3, axis='y')
            for bar, count in zip(bars, counts):
                if count > 0:
                    ax.text(bar.get_x() + bar.get_width()/2., count + 0.1, f'{count}', ha='center', va='bottom', fontweight='bold')
            buf = io.BytesIO()
            fig.savefig(buf, format='png', dpi=100, bbox_inches='tight', facecolor='#f5f5f5')
            buf.seek(0)
            chart_b64 = base64.b64encode(buf.read()).decode('utf-8')
            plt.close(fig)
            return chart_b64
        except Exception as e:
            logging.error(f"Risk chart error: {e}")
            return ""

    def generate_methodology_coverage_chart(self, findings):
        try:
            methodology_counts = {"SAST": 0, "SCA": 0, "DAST": 0, "PENTEST": 0}
            for finding in findings:
                meth = finding.get("methodology", "SAST")
                if meth in methodology_counts:
                    methodology_counts[meth] += 1
            methodologies = list(methodology_counts.keys())
            counts = [methodology_counts[m] for m in methodologies]
            colors = [METHODOLOGY_COLORS.get(m, "#6b7280") for m in methodologies]
            fig, ax = plt.subplots(figsize=(8, 5))
            bars = ax.bar(methodologies, counts, color=colors, edgecolor='white', linewidth=1.5)
            ax.set_title('Methodology Coverage', fontsize=14, fontweight='bold', color='#0a1a3b')
            ax.set_xlabel('Methodology', fontsize=12)
            ax.set_ylabel('Number of Findings', fontsize=12)
            ax.grid(True, alpha=0.3, axis='y')
            for bar, count in zip(bars, counts):
                if count > 0:
                    ax.text(bar.get_x() + bar.get_width()/2., count + 0.1, f'{count}', ha='center', va='bottom', fontweight='bold')
            buf = io.BytesIO()
            fig.savefig(buf, format='png', dpi=100, bbox_inches='tight', facecolor='#f5f5f5')
            buf.seek(0)
            chart_b64 = base64.b64encode(buf.read()).decode('utf-8')
            plt.close(fig)
            return chart_b64
        except Exception as e:
            logging.error(f"Coverage chart error: {e}")
            return ""

    def get_chartjs_data(self, findings):
        risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for finding in findings:
            risk = normalize_risk_level(finding.get("risk", "Informational"))
            if risk in risk_counts:
                risk_counts[risk] += 1
        risk_labels = list(risk_counts.keys())
        risk_values = list(risk_counts.values())
        risk_colors = [RISK_COLORS[r] for r in risk_labels]
        meth_counts = {"SAST": 0, "SCA": 0, "DAST": 0, "PENTEST": 0}
        for finding in findings:
            meth = finding.get("methodology", "SAST")
            if meth in meth_counts:
                meth_counts[meth] += 1
        meth_labels = list(meth_counts.keys())
        meth_values = list(meth_counts.values())
        meth_colors = [METHODOLOGY_COLORS.get(m, "#6b7280") for m in meth_labels]
        return {
            "risk_breakdown": {
                "labels": risk_labels,
                "datasets": [{"data": risk_values, "backgroundColor": risk_colors}]
            },
            "methodology_coverage": {
                "labels": meth_labels,
                "datasets": [{"data": meth_values, "backgroundColor": meth_colors}]
            }
        }

    def generate_professional_html_report(self, findings):
        findings = deduplicate_findings(findings)
        risk_chart_b64, coverage_chart_b64, chart_data = self.generate_charts(findings)
        total_issues = len(findings)
        critical_issues = sum(1 for f in findings if normalize_risk_level(f.get("risk")) == "Critical")
        high_issues = sum(1 for f in findings if normalize_risk_level(f.get("risk")) == "High")
        medium_issues = sum(1 for f in findings if normalize_risk_level(f.get("risk")) == "Medium")
        low_issues = sum(1 for f in findings if normalize_risk_level(f.get("risk")) == "Low")
        info_issues = sum(1 for f in findings if normalize_risk_level(f.get("risk")) == "Informational")
        findings_by_methodology = {}
        for finding in findings:
            meth = finding.get("methodology", "SAST")
            findings_by_methodology.setdefault(meth, []).append(finding)
        for meth in findings_by_methodology:
            findings_by_methodology[meth] = sorted(findings_by_methodology[meth], key=lambda f: self.framework.get_severity_level(f.get("risk", "Informational")))
        collapsible_html = self._build_collapsible_findings(findings_by_methodology)
        table_html = self._generate_findings_table_html(findings)
        target_domains = self.report_data.get("target_domains", ["portal", "auth", "app"])
        warning_html = self._get_confidential_warning_html(target_domains)
        exec_summary = self.report_data.get("executive_summary", "No summary provided.")
        import json
        chart_data_json = json.dumps(chart_data)
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        :root {{
            --primary-dark: #0a1a3b;
            --primary-light: #1a3a6a;
            --accent-gold: #FFD700;
            --accent-amber: #FFC107;
            --bg-gradient: linear-gradient(135deg, var(--primary-dark), var(--primary-light));
            --card-border: rgba(255, 193, 7, 0.2);
            --text-primary: white;
            --text-secondary: rgba(255,255,255,0.85);
            --text-muted: rgba(255,255,255,0.6);
            --border-color: rgba(255,193,7,0.3);
            --radius: 16px;
            --radius-sm: 10px;
            --font-sans: 'Inter', 'Segoe UI', Arial, sans-serif;
            --risk-critical: #ef4444;
            --risk-high: #f59e0b;
            --risk-medium: #8b5cf6;
            --risk-low: #3b82f6;
            --risk-info: #10b981;
            --meth-sast: #8b5cf6;
            --meth-sca: #10b981;
            --meth-dast: #3b82f6;
            --meth-pentest: #ff6b6b;
        }}
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            font-family: var(--font-sans);
            background: var(--bg-gradient);
            color: var(--text-primary);
            line-height: 1.6;
            padding: clamp(16px, 4vw, 32px);
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: rgba(15,23,42,0.95);
            border-radius: var(--radius);
            padding: clamp(24px, 5vw, 40px);
            border: 2px solid var(--border-color);
            backdrop-filter: blur(10px);
        }}
        .header {{
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 30px 20px;
            background: var(--bg-gradient);
            border-radius: var(--radius);
            margin-bottom: 30px;
            isolation: isolate;
            position: relative;
        }}
        .header h1 {{
            color: var(--accent-gold);
            font-size: clamp(1.8rem, 5vw, 2.8rem);
            text-align: center;
            border-bottom: 4px solid var(--accent-gold);
            padding-bottom: 15px;
        }}
        .confidential-warning {{
            background: linear-gradient(135deg, rgba(239,68,68,0.2), rgba(220,38,38,0.1));
            border-left: 6px solid var(--risk-critical);
            border-radius: var(--radius-sm);
            padding: 16px 24px;
            margin-bottom: 30px;
            display: flex;
            align-items: center;
            gap: 16px;
            flex-wrap: wrap;
        }}
        .confidential-warning i {{ color: var(--risk-critical); font-size: 1.5rem; }}
        .grid-2 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 24px; margin: 24px 0; }}
        .card {{
            background: rgba(15,23,42,0.7);
            backdrop-filter: blur(5px);
            border-radius: var(--radius-sm);
            padding: 24px;
            border: 1px solid var(--card-border);
            transition: 0.2s;
        }}
        .card:hover {{ background: rgba(15,23,42,0.85); border-color: var(--accent-gold); transform: translateY(-2px); }}
        .metric-card {{ text-align: center; border-top: 4px solid var(--accent-gold); }}
        .metric-value {{ font-size: clamp(2rem, 6vw, 3rem); font-weight: 900; background: linear-gradient(135deg, var(--accent-gold), var(--accent-amber)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }}
        .metric-label {{ font-size: 1rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 1px; }}
        .grid-4 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; margin: 20px 0; }}
        .section-title {{ display: flex; align-items: center; gap: 12px; margin: 30px 0 20px; color: var(--accent-gold); border-bottom: 2px solid var(--border-color); padding-bottom: 12px; font-size: 1.5rem; font-weight: 600; }}
        .analytics-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 24px; }}
        @media (max-width: 900px) {{ .analytics-grid {{ grid-template-columns: 1fr; }} }}
        .chart-container {{ position: relative; height: 300px; width: 100%; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; color: white; }}
        .critical-badge {{ background: linear-gradient(135deg, var(--risk-critical), #dc2626); }}
        .high-badge {{ background: linear-gradient(135deg, var(--risk-high), #d97706); }}
        .medium-badge {{ background: linear-gradient(135deg, var(--risk-medium), #7c3aed); }}
        .low-badge {{ background: linear-gradient(135deg, var(--risk-low), #1d4ed8); }}
        .info-badge {{ background: linear-gradient(135deg, var(--risk-info), #059669); }}
        .methodology-badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; color: white; }}
        .sast-badge {{ background: var(--meth-sast); }} .sca-badge {{ background: var(--meth-sca); }} .dast-badge {{ background: var(--meth-dast); }} .pentest-badge {{ background: var(--meth-pentest); }}
        .finding-table {{ width: 100%; border-collapse: collapse; margin: 24px 0; background: rgba(15,23,42,0.8); border-radius: var(--radius-sm); overflow: hidden; }}
        .finding-table th {{ background: rgba(255,193,7,0.2); color: var(--accent-gold); padding: 16px; text-align: left; font-weight: 600; }}
        .finding-table td {{ padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.1); color: var(--text-secondary); }}
        .finding-table tr:hover {{ background: rgba(255,193,7,0.1); }}
        .findings-container {{ margin: 30px 0; }}
        .methodology-group {{ margin-bottom: 20px; border-radius: var(--radius-sm); overflow: hidden; border: 1px solid var(--border-color); background: rgba(15,23,42,0.8); }}
        .methodology-header {{ width: 100%; padding: 18px 24px; background: linear-gradient(135deg, rgba(26,58,106,0.9), rgba(15,23,42,0.95)); border: none; display: flex; align-items: center; justify-content: space-between; cursor: pointer; transition: 0.3s; color: var(--text-primary); font-weight: 600; font-size: 1.1rem; border-bottom: 2px solid transparent; }}
        .methodology-header:hover {{ background: rgba(255,193,7,0.1); border-bottom-color: var(--accent-gold); }}
        .methodology-header-left {{ display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }}
        .methodology-header i {{ font-size: 1.2rem; transition: transform 0.3s; }}
        .methodology-header[aria-expanded="true"] i.fa-chevron-down {{ transform: rotate(180deg); }}
        .methodology-badge {{ background: var(--accent-gold); color: var(--primary-dark); padding: 4px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: 700; }}
        .finding-item {{ padding: 16px 24px; border-bottom: 1px solid rgba(255,193,7,0.1); }}
        .finding-item:hover {{ background: rgba(255,193,7,0.05); }}
        .finding-summary {{ display: flex; align-items: center; justify-content: space-between; padding: 12px; background: rgba(255,193,7,0.05); border-radius: var(--radius-sm); cursor: pointer; transition: 0.2s; }}
        .finding-summary:hover {{ background: rgba(255,193,7,0.1); }}
        .finding-summary-left {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
        .finding-summary i.fa-chevron-right {{ transition: transform 0.3s; }}
        .finding-summary[aria-expanded="true"] i.fa-chevron-right {{ transform: rotate(90deg); }}
        .finding-detailed-content {{ display: none; padding: 25px; background: rgba(0,0,0,0.3); border-radius: 0 0 var(--radius-sm) var(--radius-sm); margin-top: 15px; border: 1px solid rgba(255,193,7,0.1); }}
        .finding-detailed-content.show {{ display: block; }}
        .collapse-content {{ display: none; background: rgba(10,20,40,0.95); }}
        .collapse-content.show {{ display: block; }}
        .risk-indicator {{ width: 12px; height: 12px; border-radius: 50%; display: inline-block; }}
        .cvss-box {{ display: inline-block; padding: 4px 12px; background: rgba(139,92,246,0.2); border-radius: 20px; font-size: 0.8rem; color: var(--text-secondary); }}
        .remediation-box {{ margin-top: 16px; padding: 16px; background: rgba(16,185,129,0.1); border-left: 4px solid var(--risk-info); border-radius: var(--radius-sm); }}
        .finding-meta {{ display: flex; gap: 20px; flex-wrap: wrap; margin-top: 16px; padding-top: 16px; border-top: 1px solid rgba(255,255,255,0.1); font-size: 0.9rem; color: var(--text-muted); }}

        @media print {
            body { background:#fff !important; color:#111 !important; padding:0 !important; }
            .container { max-width:none !important; border:0 !important; box-shadow:none !important; background:#fff !important; }
            .header { background:#0a1a3b !important; color:#fff !important; break-inside:avoid; }
            .card,.methodology-group { break-inside:avoid; box-shadow:none !important; }
            button { display:none !important; }
            .finding-detailed-content { display:block !important; }
            .collapse-content { display:block !important; }
        }
        .footer {{ margin-top: 50px; padding-top: 24px; border-top: 1px solid var(--border-color); text-align: center; color: var(--text-muted); font-size: 0.9rem; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div style="width:100%;display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap;">
                <div style="display:flex;align-items:center;gap:16px;">
                    <img src="/logo.png" alt="EAII Security" style="width:72px;height:72px;object-fit:contain;background:#fff;border-radius:14px;padding:6px;">
                    <div>
                        <div style="font-size:.78rem;letter-spacing:2px;color:var(--accent-gold);font-weight:800;">EAII SECURITY</div>
                        <h1 style="margin:4px 0 0;">Security Assessment Report</h1>
                        <p style="color:var(--text-secondary);margin:5px 0 0;">Generated on {self.report_data.get('date', datetime.now().strftime('%Y-%m-%d'))}</p>
                    </div>
                </div>
                <button onclick="window.print()" style="border:1px solid var(--accent-gold);background:rgba(255,215,0,.08);color:var(--accent-gold);padding:10px 14px;border-radius:10px;font-weight:700;cursor:pointer;">
                    <i class="fas fa-print"></i> Print / Save PDF
                </button>
            </div>
        </div>
        {warning_html}
        <div class="grid-2">
            <div class="card">
                <h4>Report Details</h4>
                <p style="color: var(--text-secondary); line-height:1.8;">
                    <strong>Title:</strong> {self.report_data.get('title', 'Security Assessment')}<br>
                    <strong>Target:</strong> {self.report_data.get('target', 'N/A')}<br>
                    <strong>Date:</strong> {self.report_data.get('date', 'N/A')}<br>
                    <strong>Version:</strong> {self.report_data.get('report_version', '1.0')}<br>
                    <strong>Prepared By:</strong> {self.report_data.get('prepared_by', 'N/A')}
                </p>
            </div>
            <div class="card">
                <h4>Methodology</h4>
                <p style="color: var(--text-secondary); line-height:1.8;">
                    <strong>Methodology:</strong> {self.report_data.get('methodology', 'Full Assessment')}<br>
                    <span class="tool-badge sast-badge">SAST: SonarQube</span>
                    <span class="tool-badge sca-badge">SCA: Snyk</span>
                    <span class="tool-badge dast-badge">DAST: ZAP</span>
                    <span class="tool-badge pentest-badge">PenTest: Burp Suite</span>
                </p>
            </div>
        </div>
        <div class="grid-4">
            <div class="card metric-card"><div class="metric-value">{total_issues}</div><div class="metric-label">Total Findings</div></div>
            <div class="card metric-card" style="border-top-color:var(--risk-critical);"><div class="metric-value" style="background:linear-gradient(135deg,var(--risk-critical),#dc2626);-webkit-background-clip:text;">{critical_issues}</div><div class="metric-label">Critical</div></div>
            <div class="card metric-card" style="border-top-color:var(--risk-high);"><div class="metric-value" style="background:linear-gradient(135deg,var(--risk-high),#d97706);-webkit-background-clip:text;">{high_issues}</div><div class="metric-label">High</div></div>
            <div class="card metric-card" style="border-top-color:var(--risk-low);"><div class="metric-value" style="background:linear-gradient(135deg,var(--risk-low),#1d4ed8);-webkit-background-clip:text;">{medium_issues+low_issues+info_issues}</div><div class="metric-label">Medium/Low/Info</div></div>
        </div>
        <div class="card" style="margin:20px 0;">
            <h4 style="color:var(--accent-gold);">Executive Summary</h4>
            <p style="color:var(--text-secondary); line-height:1.8;">{exec_summary}</p>
        </div>
        <!-- Charts -->
        <div class="section-title"><i class="fas fa-chart-pie"></i> Security Analytics</div>
        <div class="analytics-grid">
            <div class="card chart-card"><h4>Risk Distribution</h4><div class="chart-container"><canvas id="riskPieChart"></canvas></div></div>
            <div class="card chart-card"><h4>Methodology Coverage</h4><div class="chart-container"><canvas id="coverageChart"></canvas></div></div>
        </div>
        <!-- Findings Table -->
        <div class="section-title"><i class="fas fa-table"></i> Findings Summary</div>
        {table_html}
        <!-- Detailed Findings -->
        <div class="section-title"><i class="fas fa-list-ul"></i> Detailed Findings by Methodology</div>
        {collapsible_html}
        <!-- Footer -->
        <div class="footer">
            <p>© {self.report_data.get('date', datetime.now().strftime('%Y')).split('-')[0]} Ethiopian Artificial Intelligence Institute. All rights reserved.</p>
            <p>This document contains confidential information. Unauthorized distribution is prohibited.</p>
        </div>
    </div>
    <script>
        const chartData = {chart_data_json};
        document.addEventListener('DOMContentLoaded', function() {{
            // Risk Pie Chart
            const ctx1 = document.getElementById('riskPieChart')?.getContext('2d');
            if (ctx1 && chartData.risk_breakdown) {{
                new Chart(ctx1, {{
                    type: 'pie',
                    data: {{
                        labels: chartData.risk_breakdown.labels,
                        datasets: [{{
                            data: chartData.risk_breakdown.datasets[0].data,
                            backgroundColor: chartData.risk_breakdown.datasets[0].backgroundColor,
                            borderColor: 'white',
                            borderWidth: 2
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            legend: {{ position: 'bottom', labels: {{ color: '#FFD700' }} }}
                        }}
                    }}
                }});
            }}
            // Coverage Chart
            const ctx2 = document.getElementById('coverageChart')?.getContext('2d');
            if (ctx2 && chartData.methodology_coverage) {{
                new Chart(ctx2, {{
                    type: 'bar',
                    data: {{
                        labels: chartData.methodology_coverage.labels,
                        datasets: [{{
                            label: 'Findings',
                            data: chartData.methodology_coverage.datasets[0].data,
                            backgroundColor: chartData.methodology_coverage.datasets[0].backgroundColor,
                            borderColor: 'white',
                            borderWidth: 1
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{ legend: {{ display: false }} }},
                        scales: {{ y: {{ beginAtZero: true, grid: {{ color: 'rgba(255,255,255,0.1)' }} }} }}
                    }}
                }});
            }}
            // Collapsible functionality
            document.querySelectorAll('.methodology-header').forEach(header => {{
                header.addEventListener('click', function() {{
                    const target = document.getElementById(this.getAttribute('aria-controls'));
                    const expanded = this.getAttribute('aria-expanded') === 'true';
                    this.setAttribute('aria-expanded', !expanded);
                    if (target) target.classList.toggle('show');
                }});
            }});
            document.querySelectorAll('.finding-summary').forEach(summary => {{
                summary.addEventListener('click', function() {{
                    const target = document.getElementById(this.getAttribute('aria-controls'));
                    const expanded = this.getAttribute('aria-expanded') === 'true';
                    this.setAttribute('aria-expanded', !expanded);
                    if (target) target.classList.toggle('show');
                }});
            }});
        }});
    </script>
</body>
</html>"""
        return html

    def _generate_findings_table_html(self, findings):
        if not findings:
            return '<div style="color:rgba(255,255,255,0.6);padding:20px;text-align:center;">No findings available</div>'
        sorted_findings = sorted(findings, key=lambda f: self.framework.get_severity_level(f.get("risk", "Informational")))
        html = '<div style="overflow-x:auto;"><table class="finding-table"><thead><tr><th>ID</th><th>Title</th><th>Risk</th><th>Category</th><th>Methodology</th><th>Priority</th><th>CVSS</th></tr></thead><tbody>'
        for f in sorted_findings:
            risk = f.get("risk", "Informational")
            risk_class = risk.lower().replace(" ", "-")
            meth = f.get("methodology", "SAST")
            finding_id = f.get("finding_id", "N/A")
            title = f.get("title", "Untitled")
            category = f.get("category", "General")
            priority = f.get("priority", "P3")
            cvss = f.get("cvss_score", "N/A")
            html += f'<tr><td style="font-family:monospace;">{finding_id}</td><td>{title}</td><td><span class="{risk_class}-badge badge">{risk}</span></td><td>{category}</td><td><span class="methodology-badge {meth.lower()}-badge">{meth}</span></td><td><span style="background:{PRIORITY_COLORS.get(priority,"#3b82f6")};padding:2px 8px;border-radius:12px;color:white;">{priority}</span></td><td>{cvss}</td></tr>'
        html += '</tbody></table></div>'
        return html

    def _build_collapsible_findings(self, findings_by_methodology):
        if not findings_by_methodology:
            return ''
        html = ''
        for meth, meth_findings in findings_by_methodology.items():
            if not meth_findings:
                continue
            meth_id = f"meth-{meth.lower()}-{uuid.uuid4().hex[:6]}"
            icon = "fa-shield-alt"
            if meth.upper() == "SAST": icon = "fa-code"
            elif meth.upper() == "SCA": icon = "fa-boxes"
            elif meth.upper() == "DAST": icon = "fa-bolt"
            elif meth.upper() in ["PENTEST", "PENETRATION"]: icon = "fa-bug"
            color_class = meth.lower()
            html += f'''
            <div class="methodology-group">
                <button class="methodology-header" aria-expanded="false" aria-controls="{meth_id}">
                    <span class="methodology-header-left">
                        <i class="fas {icon}"></i>
                        <span>{meth}</span>
                        <span class="methodology-badge">{len(meth_findings)} findings</span>
                    </span>
                    <i class="fas fa-chevron-down"></i>
                </button>
                <div id="{meth_id}" class="collapse-content">
            '''
            for idx, f in enumerate(meth_findings):
                finding_id = f"finding-{meth.lower()}-{idx}-{uuid.uuid4().hex[:6]}"
                risk = f.get("risk", "Informational")
                risk_color = RISK_COLORS.get(risk, "#6b7280")
                risk_badge = risk.lower().replace(" ", "-") + "-badge"
                title = f.get("title", "Untitled")
                cvss = f.get("cvss_score", "N/A")
                description = f.get("issue_description", "No description.")
                remediation = f.get("remediation", "No remediation.")
                cve = f.get("cwe_id", "CWE-20")
                category = f.get("category", "General")
                tool = f.get("source_tool", "Unknown")
                priority = f.get("priority", "P3")
                html += f'''
                    <div class="finding-item">
                        <div class="finding-summary" aria-expanded="false" aria-controls="{finding_id}">
                            <span class="finding-summary-left">
                                <span class="risk-indicator" style="background-color:{risk_color};"></span>
                                <span class="badge {risk_badge}">{risk}</span>
                                <strong style="color:var(--text-primary);">{title}</strong>
                                <span class="cvss-box">CVSS: {cvss}</span>
                            </span>
                            <i class="fas fa-chevron-right"></i>
                        </div>
                        <div id="{finding_id}" class="finding-detailed-content">
                            <div style="margin-bottom:20px;border-bottom:1px solid var(--border-color);padding-bottom:15px;">
                                <h4 style="color:var(--accent-gold);">{title}</h4>
                                <div style="display:flex;gap:15px;flex-wrap:wrap;">
                                    <span class="badge {risk_badge}">{risk}</span>
                                    <span class="cvss-box">CVSS: {cvss}</span>
                                    <span class="badge" style="background:var(--meth-{meth.lower()});">Methodology: {meth}</span>
                                    <span class="badge" style="background:#6b7280;">Tool: {tool}</span>
                                    <span class="badge" style="background:#8b5cf6;">Priority: {priority}</span>
                                    <span class="badge" style="background:#3b82f6;">ID: {cve}</span>
                                </div>
                            </div>
                            <div style="margin-bottom:20px;background:rgba(59,130,246,0.1);padding:16px;border-radius:var(--radius-sm);">
                                <strong style="color:var(--accent-gold);">Description</strong>
                                <p style="color:var(--text-secondary);line-height:1.6;">{description}</p>
                            </div>
                            <div class="remediation-box">
                                <strong style="color:var(--risk-info);">Remediation</strong>
                                <p style="color:var(--text-secondary);line-height:1.6;">{remediation}</p>
                            </div>
                            <div class="finding-meta">
                                <span><i class="fas fa-fingerprint"></i> <strong>ID:</strong> {cve}</span>
                                <span><i class="fas fa-chart-line"></i> <strong>CVSS:</strong> {cvss}</span>
                                <span><i class="fas fa-folder"></i> <strong>Category:</strong> {category}</span>
                            </div>
                        </div>
                    </div>
                '''
            html += '</div></div>'
        return html

    def _get_confidential_warning_html(self, targets):
        if not targets:
            targets = ["portal", "auth", "app"]
        domain_links = []
        for t in targets:
            domain_links.append(f'<strong>{t}.example.com</strong>')
        domain_list = ", ".join(domain_links[:-1]) + " and " + domain_links[-1] if len(domain_links) > 1 else domain_links[0]
        return f'''
        <div class="confidential-warning">
            <i class="fas fa-exclamation-triangle"></i>
            <div>
                <h3 style="color:#fecaca;margin:0;">CONFIDENTIAL</h3>
                <p style="margin:0;">This report contains confidential information about {domain_list}. It is intended for authorized personnel only.</p>
            </div>
        </div>
        '''

# ==================== FLASK ROUTES ====================
@app.route('/')
def index():
    return render_template_string(INDEX_TEMPLATE)

@app.route('/report-generator', methods=['GET', 'POST'])
def report_generator():
    framework = SecurityAssessmentFramework()
    conn = get_db()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add_manual':
            methodology = request.form.get('methodology')
            title = request.form.get('title')
            risk = request.form.get('risk')
            description = request.form.get('description')
            remediation = request.form.get('remediation')
            cvss = request.form.get('cvss')
            cwe = request.form.get('cwe')
            if title and methodology:
                try:
                    cvss_val = float(cvss) if cvss else 7.0
                except:
                    cvss_val = 7.0
                raw = {
                    "title": title,
                    "risk": risk,
                    "description": description,
                    "remediation": remediation,
                    "cvss_score": cvss_val,
                    "cwe_id": cwe if cwe else "CWE-20",
                    "issue_description": description,
                    "affected_component": "/",
                    "evidence": "Manual entry",
                    "sequence": 1,
                    "methodology": methodology
                }
                tool_name = framework.default_tools.get(methodology, "Manual")
                normalized = framework.normalize_finding(raw, methodology, tool_name)
                if 'pending_findings' not in session:
                    session['pending_findings'] = []
                session['pending_findings'].append(normalized)
                session.modified = True
                flash(f'Added manual {methodology} finding: {title}', 'success')
        elif action == 'upload_json':
            methodology = request.form.get('methodology')
            file = request.files.get('file')
            if file and file.filename.endswith('.json'):
                try:
                    data = json.load(file)
                    if isinstance(data, dict):
                        data = [data]
                    tool_name = framework.default_tools.get(methodology, "Unknown")
                    findings = []
                    for idx, raw in enumerate(data):
                        raw['sequence'] = idx + 1
                        raw['methodology'] = methodology
                        findings.append(framework.normalize_finding(raw, methodology, tool_name))
                    if 'pending_findings' not in session:
                        session['pending_findings'] = []
                    session['pending_findings'].extend(findings)
                    session.modified = True
                    flash(f'Uploaded {len(findings)} findings for {methodology}', 'success')
                except Exception as e:
                    flash(f'Error processing JSON: {e}', 'danger')
        elif action == 'generate_report':
            pending = session.get('pending_findings', [])
            if not pending:
                flash('No findings to generate report.', 'warning')
                return redirect(url_for('report_generator'))
            report_id = str(uuid.uuid4())
            title = request.form.get('report_title', 'Security Assessment Report')
            target = request.form.get('target', 'Web Application')
            date = datetime.now().strftime('%Y-%m-%d')
            prepared_by = request.form.get('prepared_by', 'EAII Security Team')
            report_version = request.form.get('report_version', '1.0')
            methodology = request.form.get('methodology', 'Full Assessment (SAST+SCA+DAST+PENTEST)')
            exec_summary = request.form.get('executive_summary', 'No summary provided.')
            target_domains = json.dumps(['portal', 'auth', 'app'])
            # Generate HTML report
            report_data = {
                "title": title,
                "date": date,
                "generated_by": "EAII Security Team",
                "prepared_by": prepared_by,
                "target": target,
                "target_domains": ['portal', 'auth', 'app'],
                "report_version": report_version,
                "methodology": methodology,
                "executive_summary": exec_summary,
                "findings": pending
            }
            generator = SecurityReportGenerator(report_data)
            html_report = generator.generate_professional_html_report(pending)
            # Insert report with HTML
            conn.execute('''
                INSERT INTO reports (id, title, target, date, prepared_by, report_version, methodology, executive_summary, created_at, target_domains, html_content)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (report_id, title, target, date, prepared_by, report_version, methodology, exec_summary, datetime.now().isoformat(), target_domains, html_report))
            # Insert findings
            for f in pending:
                references = json.dumps(f.get('references', []))
                targets = json.dumps(f.get('targets', []))
                poc_images = json.dumps(f.get('poc_images', []))
                conn.execute('''
                    INSERT INTO findings (
                        report_id, finding_id, title, category, risk, priority, cvss_score, cwe_id, owasp_category,
                        methodology, source_tool, affected_component, issue_description, remediation, evidence,
                        references, timestamp, count, status, assigned_to, due_date, targets, impact, poc_text,
                        poc_images, burp_suite_scan_id, burp_suite_issue_type
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ''', (
                    report_id, f.get('finding_id'), f.get('title'), f.get('category'), f.get('risk'), f.get('priority'),
                    f.get('cvss_score'), f.get('cwe_id'), f.get('owasp_category'), f.get('methodology'),
                    f.get('source_tool'), f.get('affected_component'), f.get('issue_description'), f.get('remediation'),
                    f.get('evidence'), references, f.get('timestamp'), f.get('count', 1), f.get('status', 'Open'),
                    f.get('assigned_to'), f.get('due_date'), targets, f.get('impact'), f.get('poc_text'),
                    poc_images, f.get('burp_suite_scan_id'), f.get('burp_suite_issue_type')
                ))
            conn.commit()
            conn.close()
            session.pop('pending_findings', None)
            flash(f'Report generated successfully! ID: {report_id}', 'success')
            return redirect(url_for('view_report', report_id=report_id))
    pending = session.get('pending_findings', [])
    return render_template_string(REPORT_GENERATOR_TEMPLATE, pending=pending)

@app.route('/history')
def history():
    conn = get_db()
    reports = conn.execute('SELECT * FROM reports ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template_string(HISTORY_TEMPLATE, reports=reports)

@app.route('/report/<report_id>')
def view_report(report_id):
    conn = get_db()
    report = conn.execute('SELECT html_content FROM reports WHERE id = ?', (report_id,)).fetchone()
    conn.close()
    if not report or not report['html_content']:
        flash('Report not found or HTML missing.', 'danger')
        return redirect(url_for('history'))
    return report['html_content']

@app.route('/download_report/<report_id>')
def download_report(report_id):
    conn = get_db()
    report = conn.execute('SELECT html_content, title FROM reports WHERE id = ?', (report_id,)).fetchone()
    conn.close()
    if not report or not report['html_content']:
        flash('Report not found.', 'danger')
        return redirect(url_for('history'))
    response = app.response_class(
        response=report['html_content'],
        status=200,
        mimetype='text/html'
    )
    response.headers.set('Content-Disposition', 'attachment', filename=f'report_{report_id}.html')
    return response

@app.route('/clear_pending')
def clear_pending():
    session.pop('pending_findings', None)
    flash('Pending findings cleared.', 'info')
    return redirect(url_for('report_generator'))

# ==================== TEMPLATES ====================
INDEX_TEMPLATE = '''<!doctype html><html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="icon" href="/logo.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root{--navy:#071426;--navy2:#0d2038;--panel:#101f33;--panel2:#142941;--line:rgba(255,255,255,.09);
--gold:#f4c542;--gold2:#ffdc73;--text:#f7f9fc;--muted:#9eafc4;--green:#27c78a;--red:#ef5350;
--orange:#f59e0b;--blue:#4f8cff;--purple:#9b7cff;--shadow:0 18px 55px rgba(0,0,0,.25)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:
radial-gradient(circle at 10% 0%,rgba(244,197,66,.08),transparent 28%),linear-gradient(135deg,var(--navy),#081b31 55%,#061321);
color:var(--text);font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;min-height:100vh}
a{color:inherit;text-decoration:none}.app{max-width:1480px;margin:auto;padding:24px}
.topbar{position:sticky;top:12px;z-index:20;display:flex;align-items:center;justify-content:space-between;gap:18px;
padding:13px 18px;background:rgba(8,24,43,.88);backdrop-filter:blur(18px);border:1px solid var(--line);
border-radius:18px;box-shadow:var(--shadow);margin-bottom:28px}
.brand{display:flex;align-items:center;gap:12px;min-width:0}.brand img{width:46px;height:46px;object-fit:contain;border-radius:12px;
background:#fff;padding:4px}.brand-title{font-weight:800;font-size:15px}.brand-sub{font-size:11px;color:var(--muted);margin-top:2px}
.nav{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}.nav a,.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
border:1px solid var(--line);border-radius:11px;padding:10px 14px;font-weight:700;font-size:13px;transition:.2s}
.nav a:hover,.btn:hover{transform:translateY(-1px);border-color:rgba(244,197,66,.5)}.btn-gold{background:linear-gradient(135deg,var(--gold),var(--gold2));
color:#172033;border:none}.btn-outline{background:rgba(255,255,255,.025)}.btn-danger{border-color:rgba(239,83,80,.4);color:#ff9d9a}
.hero{display:flex;justify-content:space-between;gap:24px;align-items:flex-end;padding:34px;border:1px solid var(--line);
border-radius:24px;background:linear-gradient(135deg,rgba(20,41,65,.96),rgba(10,27,47,.88));box-shadow:var(--shadow);margin-bottom:24px}
.eyebrow{color:var(--gold);font-weight:800;letter-spacing:1.6px;font-size:11px;text-transform:uppercase}.hero h1{margin:8px 0;font-size:clamp(28px,4vw,46px);line-height:1.08}.hero p{margin:0;color:var(--muted);max-width:720px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}.grid-2{display:grid;grid-template-columns:repeat(2,1fr);gap:18px}
.card{background:linear-gradient(180deg,rgba(18,36,58,.96),rgba(10,26,44,.96));border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:0 10px 35px rgba(0,0,0,.12)}
.card h2,.card h3{margin:0 0 10px}.metric{position:relative;overflow:hidden}.metric:after{content:"";position:absolute;right:-35px;top:-35px;width:100px;height:100px;
border-radius:50%;background:rgba(244,197,66,.06)}.metric-value{font-size:34px;font-weight:800}.metric-label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.8px;margin-top:5px}
.method{border-top:3px solid var(--gold)}.method.sast{border-top-color:var(--purple)}.method.sca{border-top-color:var(--green)}.method.dast{border-top-color:var(--blue)}.method.pentest{border-top-color:#ff6b6b}
.iconbox{width:40px;height:40px;border-radius:12px;display:grid;place-items:center;background:rgba(244,197,66,.09);color:var(--gold);margin-bottom:14px}
.section-title{display:flex;align-items:center;gap:10px;margin:28px 0 14px;font-size:18px}.section-title i{color:var(--gold)}
.form-control,.form-select,textarea,input[type=file]{width:100%;background:#0a1a2d!important;color:var(--text)!important;border:1px solid var(--line)!important;border-radius:10px;padding:11px 12px}
.form-control:focus,.form-select:focus{outline:none;border-color:var(--gold)!important;box-shadow:0 0 0 3px rgba(244,197,66,.1)}
label{font-size:12px;color:var(--muted);font-weight:700;margin-bottom:6px;display:block}.field{margin-bottom:14px}
.pending{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:13px 15px;border:1px solid var(--line);border-radius:12px;background:rgba(255,255,255,.025);margin-bottom:8px}
.badge{display:inline-flex;align-items:center;border-radius:999px;padding:4px 9px;font-size:10px;font-weight:800;text-transform:uppercase}.critical{background:rgba(239,83,80,.18);color:#ff8c89}.high{background:rgba(245,158,11,.18);color:#ffc55c}.medium{background:rgba(155,124,255,.18);color:#bca8ff}.low{background:rgba(79,140,255,.18);color:#8db5ff}.informational{background:rgba(39,199,138,.18);color:#63e0af}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:14px}.table{width:100%;border-collapse:collapse}.table th,.table td{padding:13px 14px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}.table th{color:var(--gold);font-size:11px;text-transform:uppercase;letter-spacing:.7px}.table td{color:#d9e2ee;font-size:13px}
.alert{padding:12px 15px;border-radius:12px;margin-bottom:14px;border:1px solid var(--line);background:rgba(255,255,255,.04)}.alert-success{border-color:rgba(39,199,138,.35)}.alert-danger{border-color:rgba(239,83,80,.35)}
.footer{padding:30px 0;color:var(--muted);text-align:center;font-size:11px}.muted{color:var(--muted)}.empty{text-align:center;padding:35px;color:var(--muted)}
@media(max-width:1000px){.grid{grid-template-columns:repeat(2,1fr)}.hero{flex-direction:column;align-items:flex-start}}
@media(max-width:650px){.app{padding:12px}.topbar{position:static;flex-direction:column;align-items:stretch}.nav{justify-content:stretch}.nav a{flex:1}.grid,.grid-2{grid-template-columns:1fr}.hero{padding:24px}.brand-title{font-size:14px}}
</style>
<title>EAII Security Platform</title></head><body>
<div class="app">
<header class="topbar"><a class="brand" href="{{ url_for('index') }}">
<img src="/logo.png" alt="EAII Security logo"><div><div class="brand-title">EAII SECURITY PLATFORM</div><div class="brand-sub">Application Security Assessment</div></div></a>
<nav class="nav"><a href="{{ url_for('index') }}"><i class="fas fa-grid-2"></i> Dashboard</a><a href="{{ url_for('report_generator') }}"><i class="fas fa-file-shield"></i> Reports</a><a href="{{ url_for('history') }}"><i class="fas fa-clock-rotate-left"></i> History</a></nav></header>
<section class="hero"><div><div class="eyebrow">EAII · Security Operations</div><h1>Security Assessment Framework</h1><p>Unified workspace for SAST, SCA, DAST and penetration-testing findings, reporting and assessment history.</p></div>
<a class="btn btn-gold" href="{{ url_for('report_generator') }}"><i class="fas fa-plus"></i> Create Assessment</a></section>
<div class="section-title"><i class="fas fa-layer-group"></i> Assessment Coverage</div>
<div class="grid">
<div class="card method sast"><div class="iconbox"><i class="fas fa-code"></i></div><h3>SAST</h3><p class="muted">Static application security testing and source-code findings.</p><small class="muted">SonarQube · Checkmarx · Fortify · Veracode</small></div>
<div class="card method sca"><div class="iconbox"><i class="fas fa-cubes"></i></div><h3>SCA</h3><p class="muted">Dependency and open-source component risk analysis.</p><small class="muted">Snyk · OWASP Dependency-Check · Black Duck</small></div>
<div class="card method dast"><div class="iconbox"><i class="fas fa-bolt"></i></div><h3>DAST</h3><p class="muted">Dynamic testing of running applications and endpoints.</p><small class="muted">ZAP · Burp Suite · Acunetix · Nessus</small></div>
<div class="card method pentest"><div class="iconbox"><i class="fas fa-bug"></i></div><h3>PenTest</h3><p class="muted">Manual penetration testing and proof-of-concept findings.</p><small class="muted">Burp Suite Professional · Community · Enterprise</small></div>
</div>
<div class="section-title"><i class="fas fa-rocket"></i> Quick Actions</div>
<div class="grid-2"><a class="card" href="{{ url_for('report_generator') }}"><h3><i class="fas fa-file-circle-plus" style="color:var(--gold)"></i> Generate Security Report</h3><p class="muted">Add manual findings, upload JSON and produce a professional assessment report.</p></a>
<a class="card" href="{{ url_for('history') }}"><h3><i class="fas fa-clock-rotate-left" style="color:var(--gold)"></i> Assessment History</h3><p class="muted">Review generated reports and open or download previous assessments.</p></a></div>
<footer class="footer">© 2026 Ethiopian Artificial Intelligence Institute · Security Team</footer></div></body></html>'''

REPORT_GENERATOR_TEMPLATE = '''<!doctype html><html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="icon" href="/logo.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root{--navy:#071426;--navy2:#0d2038;--panel:#101f33;--panel2:#142941;--line:rgba(255,255,255,.09);
--gold:#f4c542;--gold2:#ffdc73;--text:#f7f9fc;--muted:#9eafc4;--green:#27c78a;--red:#ef5350;
--orange:#f59e0b;--blue:#4f8cff;--purple:#9b7cff;--shadow:0 18px 55px rgba(0,0,0,.25)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:
radial-gradient(circle at 10% 0%,rgba(244,197,66,.08),transparent 28%),linear-gradient(135deg,var(--navy),#081b31 55%,#061321);
color:var(--text);font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;min-height:100vh}
a{color:inherit;text-decoration:none}.app{max-width:1480px;margin:auto;padding:24px}
.topbar{position:sticky;top:12px;z-index:20;display:flex;align-items:center;justify-content:space-between;gap:18px;
padding:13px 18px;background:rgba(8,24,43,.88);backdrop-filter:blur(18px);border:1px solid var(--line);
border-radius:18px;box-shadow:var(--shadow);margin-bottom:28px}
.brand{display:flex;align-items:center;gap:12px;min-width:0}.brand img{width:46px;height:46px;object-fit:contain;border-radius:12px;
background:#fff;padding:4px}.brand-title{font-weight:800;font-size:15px}.brand-sub{font-size:11px;color:var(--muted);margin-top:2px}
.nav{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}.nav a,.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
border:1px solid var(--line);border-radius:11px;padding:10px 14px;font-weight:700;font-size:13px;transition:.2s}
.nav a:hover,.btn:hover{transform:translateY(-1px);border-color:rgba(244,197,66,.5)}.btn-gold{background:linear-gradient(135deg,var(--gold),var(--gold2));
color:#172033;border:none}.btn-outline{background:rgba(255,255,255,.025)}.btn-danger{border-color:rgba(239,83,80,.4);color:#ff9d9a}
.hero{display:flex;justify-content:space-between;gap:24px;align-items:flex-end;padding:34px;border:1px solid var(--line);
border-radius:24px;background:linear-gradient(135deg,rgba(20,41,65,.96),rgba(10,27,47,.88));box-shadow:var(--shadow);margin-bottom:24px}
.eyebrow{color:var(--gold);font-weight:800;letter-spacing:1.6px;font-size:11px;text-transform:uppercase}.hero h1{margin:8px 0;font-size:clamp(28px,4vw,46px);line-height:1.08}.hero p{margin:0;color:var(--muted);max-width:720px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}.grid-2{display:grid;grid-template-columns:repeat(2,1fr);gap:18px}
.card{background:linear-gradient(180deg,rgba(18,36,58,.96),rgba(10,26,44,.96));border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:0 10px 35px rgba(0,0,0,.12)}
.card h2,.card h3{margin:0 0 10px}.metric{position:relative;overflow:hidden}.metric:after{content:"";position:absolute;right:-35px;top:-35px;width:100px;height:100px;
border-radius:50%;background:rgba(244,197,66,.06)}.metric-value{font-size:34px;font-weight:800}.metric-label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.8px;margin-top:5px}
.method{border-top:3px solid var(--gold)}.method.sast{border-top-color:var(--purple)}.method.sca{border-top-color:var(--green)}.method.dast{border-top-color:var(--blue)}.method.pentest{border-top-color:#ff6b6b}
.iconbox{width:40px;height:40px;border-radius:12px;display:grid;place-items:center;background:rgba(244,197,66,.09);color:var(--gold);margin-bottom:14px}
.section-title{display:flex;align-items:center;gap:10px;margin:28px 0 14px;font-size:18px}.section-title i{color:var(--gold)}
.form-control,.form-select,textarea,input[type=file]{width:100%;background:#0a1a2d!important;color:var(--text)!important;border:1px solid var(--line)!important;border-radius:10px;padding:11px 12px}
.form-control:focus,.form-select:focus{outline:none;border-color:var(--gold)!important;box-shadow:0 0 0 3px rgba(244,197,66,.1)}
label{font-size:12px;color:var(--muted);font-weight:700;margin-bottom:6px;display:block}.field{margin-bottom:14px}
.pending{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:13px 15px;border:1px solid var(--line);border-radius:12px;background:rgba(255,255,255,.025);margin-bottom:8px}
.badge{display:inline-flex;align-items:center;border-radius:999px;padding:4px 9px;font-size:10px;font-weight:800;text-transform:uppercase}.critical{background:rgba(239,83,80,.18);color:#ff8c89}.high{background:rgba(245,158,11,.18);color:#ffc55c}.medium{background:rgba(155,124,255,.18);color:#bca8ff}.low{background:rgba(79,140,255,.18);color:#8db5ff}.informational{background:rgba(39,199,138,.18);color:#63e0af}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:14px}.table{width:100%;border-collapse:collapse}.table th,.table td{padding:13px 14px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}.table th{color:var(--gold);font-size:11px;text-transform:uppercase;letter-spacing:.7px}.table td{color:#d9e2ee;font-size:13px}
.alert{padding:12px 15px;border-radius:12px;margin-bottom:14px;border:1px solid var(--line);background:rgba(255,255,255,.04)}.alert-success{border-color:rgba(39,199,138,.35)}.alert-danger{border-color:rgba(239,83,80,.35)}
.footer{padding:30px 0;color:var(--muted);text-align:center;font-size:11px}.muted{color:var(--muted)}.empty{text-align:center;padding:35px;color:var(--muted)}
@media(max-width:1000px){.grid{grid-template-columns:repeat(2,1fr)}.hero{flex-direction:column;align-items:flex-start}}
@media(max-width:650px){.app{padding:12px}.topbar{position:static;flex-direction:column;align-items:stretch}.nav{justify-content:stretch}.nav a{flex:1}.grid,.grid-2{grid-template-columns:1fr}.hero{padding:24px}.brand-title{font-size:14px}}
</style>
<title>Report Generator · EAII Security</title></head><body>
<div class="app"><header class="topbar"><a class="brand" href="{{ url_for('index') }}"><img src="/logo.png" alt="EAII Security logo"><div><div class="brand-title">EAII SECURITY PLATFORM</div><div class="brand-sub">Report Generator</div></div></a>
<nav class="nav"><a href="{{ url_for('index') }}">Dashboard</a><a href="{{ url_for('history') }}">History</a></nav></header>
<section class="hero"><div><div class="eyebrow">Assessment Workspace</div><h1>Report Generator</h1><p>Build a structured security assessment from manual findings or tool-exported JSON.</p></div></section>
{% with messages = get_flashed_messages(with_categories=true) %}{% if messages %}{% for category, message in messages %}<div class="alert alert-{{ category }}">{{ message }}</div>{% endfor %}{% endif %}{% endwith %}
<div class="grid-2">
<div class="card"><h2><i class="fas fa-pen-to-square" style="color:var(--gold)"></i> Manual Finding</h2><form method="POST"><input type="hidden" name="action" value="add_manual">
<div class="field"><label>Methodology</label><select name="methodology" class="form-select" required><option>SAST</option><option>SCA</option><option>DAST</option><option>PENTEST</option></select></div>
<div class="field"><label>Finding Title</label><input name="title" class="form-control" required placeholder="e.g. SQL Injection"></div>
<div class="field"><label>Risk</label><select name="risk" class="form-select"><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Informational</option></select></div>
<div class="field"><label>Description</label><textarea name="description" class="form-control" rows="4"></textarea></div>
<div class="field"><label>Remediation</label><textarea name="remediation" class="form-control" rows="4"></textarea></div>
<div class="grid-2"><div class="field"><label>CVSS</label><input name="cvss" class="form-control" placeholder="7.5"></div><div class="field"><label>CWE ID</label><input name="cwe" class="form-control" placeholder="CWE-89"></div></div>
<button class="btn btn-gold" type="submit"><i class="fas fa-plus"></i> Add Finding</button></form></div>
<div class="card"><h2><i class="fas fa-file-arrow-up" style="color:var(--gold)"></i> Upload JSON</h2><p class="muted">Import findings from SAST, SCA, DAST or PenTest exports.</p>
<form method="POST" enctype="multipart/form-data"><input type="hidden" name="action" value="upload_json">
<div class="field"><label>Methodology</label><select name="methodology" class="form-select" required><option>SAST</option><option>SCA</option><option>DAST</option><option>PENTEST</option></select></div>
<div class="field"><label>JSON File</label><input type="file" name="file" class="form-control" accept=".json" required></div>
<button class="btn btn-gold" type="submit"><i class="fas fa-upload"></i> Import Findings</button></form></div></div>
<div class="section-title"><i class="fas fa-list-check"></i> Pending Findings <span class="badge" style="background:rgba(244,197,66,.12);color:var(--gold)">{{ pending|length }}</span></div>
<div class="card">{% if pending %}{% for f in pending %}<div class="pending"><div><span class="badge {{ f.risk.lower().replace(' ','-') }}">{{ f.risk }}</span> <strong>{{ f.title }}</strong><span class="muted"> · {{ f.methodology }}</span></div><span class="muted">CVSS {{ f.cvss_score }}</span></div>{% endfor %}
<div style="margin-top:14px"><a class="btn btn-danger" href="{{ url_for('clear_pending') }}"><i class="fas fa-trash"></i> Clear All</a></div>{% else %}<div class="empty">No pending findings. Add a finding or import a JSON file.</div>{% endif %}</div>
<div class="section-title"><i class="fas fa-file-circle-check"></i> Report Details</div>
<div class="card"><form method="POST"><input type="hidden" name="action" value="generate_report"><div class="grid-2">
<div><div class="field"><label>Report Title</label><input name="report_title" class="form-control" value="Security Assessment Report"></div><div class="field"><label>Target System</label><input name="target" class="form-control" value="Web Application"></div><div class="field"><label>Prepared By</label><input name="prepared_by" class="form-control" value="EAII Security Team"></div></div>
<div><div class="field"><label>Report Version</label><input name="report_version" class="form-control" value="1.0"></div><div class="field"><label>Methodology</label><input name="methodology" class="form-control" value="Full Assessment (SAST+SCA+DAST+PENTEST)"></div><div class="field"><label>Executive Summary</label><textarea name="executive_summary" class="form-control" rows="4">No summary provided.</textarea></div></div></div>
<button class="btn btn-gold" style="width:100%;padding:14px" type="submit" {% if not pending %}disabled{% endif %}><i class="fas fa-file-export"></i> Generate Professional Report</button>
{% if not pending %}<p class="muted" style="margin:10px 0 0">Add at least one finding before generating the report.</p>{% endif %}</form></div>
<footer class="footer">© 2026 Ethiopian Artificial Intelligence Institute · Security Team</footer></div></body></html>'''

HISTORY_TEMPLATE = '''<!doctype html><html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="icon" href="/logo.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root{--navy:#071426;--navy2:#0d2038;--panel:#101f33;--panel2:#142941;--line:rgba(255,255,255,.09);
--gold:#f4c542;--gold2:#ffdc73;--text:#f7f9fc;--muted:#9eafc4;--green:#27c78a;--red:#ef5350;
--orange:#f59e0b;--blue:#4f8cff;--purple:#9b7cff;--shadow:0 18px 55px rgba(0,0,0,.25)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:
radial-gradient(circle at 10% 0%,rgba(244,197,66,.08),transparent 28%),linear-gradient(135deg,var(--navy),#081b31 55%,#061321);
color:var(--text);font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;min-height:100vh}
a{color:inherit;text-decoration:none}.app{max-width:1480px;margin:auto;padding:24px}
.topbar{position:sticky;top:12px;z-index:20;display:flex;align-items:center;justify-content:space-between;gap:18px;
padding:13px 18px;background:rgba(8,24,43,.88);backdrop-filter:blur(18px);border:1px solid var(--line);
border-radius:18px;box-shadow:var(--shadow);margin-bottom:28px}
.brand{display:flex;align-items:center;gap:12px;min-width:0}.brand img{width:46px;height:46px;object-fit:contain;border-radius:12px;
background:#fff;padding:4px}.brand-title{font-weight:800;font-size:15px}.brand-sub{font-size:11px;color:var(--muted);margin-top:2px}
.nav{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}.nav a,.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
border:1px solid var(--line);border-radius:11px;padding:10px 14px;font-weight:700;font-size:13px;transition:.2s}
.nav a:hover,.btn:hover{transform:translateY(-1px);border-color:rgba(244,197,66,.5)}.btn-gold{background:linear-gradient(135deg,var(--gold),var(--gold2));
color:#172033;border:none}.btn-outline{background:rgba(255,255,255,.025)}.btn-danger{border-color:rgba(239,83,80,.4);color:#ff9d9a}
.hero{display:flex;justify-content:space-between;gap:24px;align-items:flex-end;padding:34px;border:1px solid var(--line);
border-radius:24px;background:linear-gradient(135deg,rgba(20,41,65,.96),rgba(10,27,47,.88));box-shadow:var(--shadow);margin-bottom:24px}
.eyebrow{color:var(--gold);font-weight:800;letter-spacing:1.6px;font-size:11px;text-transform:uppercase}.hero h1{margin:8px 0;font-size:clamp(28px,4vw,46px);line-height:1.08}.hero p{margin:0;color:var(--muted);max-width:720px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}.grid-2{display:grid;grid-template-columns:repeat(2,1fr);gap:18px}
.card{background:linear-gradient(180deg,rgba(18,36,58,.96),rgba(10,26,44,.96));border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:0 10px 35px rgba(0,0,0,.12)}
.card h2,.card h3{margin:0 0 10px}.metric{position:relative;overflow:hidden}.metric:after{content:"";position:absolute;right:-35px;top:-35px;width:100px;height:100px;
border-radius:50%;background:rgba(244,197,66,.06)}.metric-value{font-size:34px;font-weight:800}.metric-label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.8px;margin-top:5px}
.method{border-top:3px solid var(--gold)}.method.sast{border-top-color:var(--purple)}.method.sca{border-top-color:var(--green)}.method.dast{border-top-color:var(--blue)}.method.pentest{border-top-color:#ff6b6b}
.iconbox{width:40px;height:40px;border-radius:12px;display:grid;place-items:center;background:rgba(244,197,66,.09);color:var(--gold);margin-bottom:14px}
.section-title{display:flex;align-items:center;gap:10px;margin:28px 0 14px;font-size:18px}.section-title i{color:var(--gold)}
.form-control,.form-select,textarea,input[type=file]{width:100%;background:#0a1a2d!important;color:var(--text)!important;border:1px solid var(--line)!important;border-radius:10px;padding:11px 12px}
.form-control:focus,.form-select:focus{outline:none;border-color:var(--gold)!important;box-shadow:0 0 0 3px rgba(244,197,66,.1)}
label{font-size:12px;color:var(--muted);font-weight:700;margin-bottom:6px;display:block}.field{margin-bottom:14px}
.pending{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:13px 15px;border:1px solid var(--line);border-radius:12px;background:rgba(255,255,255,.025);margin-bottom:8px}
.badge{display:inline-flex;align-items:center;border-radius:999px;padding:4px 9px;font-size:10px;font-weight:800;text-transform:uppercase}.critical{background:rgba(239,83,80,.18);color:#ff8c89}.high{background:rgba(245,158,11,.18);color:#ffc55c}.medium{background:rgba(155,124,255,.18);color:#bca8ff}.low{background:rgba(79,140,255,.18);color:#8db5ff}.informational{background:rgba(39,199,138,.18);color:#63e0af}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:14px}.table{width:100%;border-collapse:collapse}.table th,.table td{padding:13px 14px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}.table th{color:var(--gold);font-size:11px;text-transform:uppercase;letter-spacing:.7px}.table td{color:#d9e2ee;font-size:13px}
.alert{padding:12px 15px;border-radius:12px;margin-bottom:14px;border:1px solid var(--line);background:rgba(255,255,255,.04)}.alert-success{border-color:rgba(39,199,138,.35)}.alert-danger{border-color:rgba(239,83,80,.35)}
.footer{padding:30px 0;color:var(--muted);text-align:center;font-size:11px}.muted{color:var(--muted)}.empty{text-align:center;padding:35px;color:var(--muted)}
@media(max-width:1000px){.grid{grid-template-columns:repeat(2,1fr)}.hero{flex-direction:column;align-items:flex-start}}
@media(max-width:650px){.app{padding:12px}.topbar{position:static;flex-direction:column;align-items:stretch}.nav{justify-content:stretch}.nav a{flex:1}.grid,.grid-2{grid-template-columns:1fr}.hero{padding:24px}.brand-title{font-size:14px}}
</style>
<title>Assessment History · EAII Security</title></head><body>
<div class="app"><header class="topbar"><a class="brand" href="{{ url_for('index') }}"><img src="/logo.png" alt="EAII Security logo"><div><div class="brand-title">EAII SECURITY PLATFORM</div><div class="brand-sub">Assessment History</div></div></a>
<nav class="nav"><a href="{{ url_for('index') }}">Dashboard</a><a href="{{ url_for('report_generator') }}">New Report</a></nav></header>
<section class="hero"><div><div class="eyebrow">Reports & Records</div><h1>Assessment History</h1><p>Review generated security assessments and open their full reports.</p></div></section>
<div class="card"><div class="table-wrap"><table class="table"><thead><tr><th>Report</th><th>Target</th><th>Date</th><th>Methodology</th><th>Actions</th></tr></thead><tbody>
{% for r in reports %}<tr><td><strong>{{ r.title }}</strong></td><td>{{ r.target }}</td><td>{{ r.date }}</td><td>{{ r.methodology[:45] }}{% if r.methodology|length > 45 %}…{% endif %}</td><td><a class="btn" href="{{ url_for('view_report', report_id=r.id) }}" target="_blank"><i class="fas fa-eye"></i> View</a> <a class="btn btn-gold" href="{{ url_for('download_report', report_id=r.id) }}"><i class="fas fa-download"></i> HTML</a></td></tr>
{% else %}<tr><td colspan="5" class="empty">No reports found.</td></tr>{% endfor %}</tbody></table></div></div>
<footer class="footer">© 2026 Ethiopian Artificial Intelligence Institute · Security Team</footer></div></body></html>'''

# ==================== RUN (for local development) ====================
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
