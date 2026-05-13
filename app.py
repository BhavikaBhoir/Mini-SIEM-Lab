"""
Mini SIEM Lab - SOC Monitoring System
Advanced Flask SIEM Dashboard
"""

import os
import io
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, send_file, jsonify, flash
)
from flask_sqlalchemy import SQLAlchemy
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle,
    Paragraph, Spacer, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from detector import detect_threats, THREAT_SIGNATURES

# ==============================
# APP INITIALIZATION
# ==============================

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY", "minisiem_super_secret_key_2024_XyZ9!")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///siem.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

db = SQLAlchemy(app)

# ==============================
# DATABASE MODELS
# ==============================

class Threat(db.Model):
    __tablename__ = "threats"

    id           = db.Column(db.Integer, primary_key=True)
    threat_type  = db.Column(db.String(100), nullable=False)
    severity     = db.Column(db.String(50),  nullable=False)
    source_ip    = db.Column(db.String(50),  nullable=False, default="Unknown")
    description  = db.Column(db.String(255), nullable=True)
    status       = db.Column(db.String(30),  nullable=False, default="Open")
    timestamp    = db.Column(db.DateTime,    nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id":          self.id,
            "threat_type": self.threat_type,
            "severity":    self.severity,
            "source_ip":   self.source_ip,
            "description": self.description or "",
            "status":      self.status,
            "timestamp":   self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        }


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id        = db.Column(db.Integer, primary_key=True)
    action    = db.Column(db.String(200), nullable=False)
    user      = db.Column(db.String(100), nullable=False, default="admin")
    timestamp = db.Column(db.DateTime,   nullable=False, default=datetime.utcnow)


with app.app_context():
    db.create_all()

# ==============================
# AUTH DECORATOR
# ==============================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ==============================
# HELPERS
# ==============================

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

def log_action(action):
    entry = AuditLog(action=action, user=session.get("username", "unknown"))
    db.session.add(entry)
    db.session.commit()

def update_database():
    """Read new log lines, detect threats, save to DB (skip duplicates)."""
    threats = detect_threats()
    added = 0
    for t in threats:
        exists = Threat.query.filter_by(
            threat_type=t["type"],
            source_ip=t["ip"],
            description=t.get("description", "")
        ).filter(
            Threat.timestamp >= datetime.utcnow() - timedelta(minutes=1)
        ).first()
        if not exists:
            new_threat = Threat(
                threat_type=t["type"],
                severity=t["severity"],
                source_ip=t["ip"],
                description=t.get("description", ""),
            )
            db.session.add(new_threat)
            added += 1
    db.session.commit()
    return added

# ==============================
# AUTH ROUTES
# ==============================

@app.route("/")
def index():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Hardcoded demo credentials — replace with DB users for production
        USERS = {"admin": "admin123", "analyst": "analyst456"}

        if username in USERS and USERS[username] == password:
            session["logged_in"] = True
            session["username"]  = username
            session["role"]      = "Admin" if username == "admin" else "Analyst"
            session.permanent    = True
            log_action(f"User '{username}' logged in")
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid credentials. Please try again."
            log_action(f"Failed login attempt for username '{username}'")

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    user = session.get("username", "unknown")
    session.clear()
    log_action(f"User '{user}' logged out")
    flash("You have been securely logged out.", "info")
    return redirect(url_for("login"))

# ==============================
# DASHBOARD
# ==============================

@app.route("/dashboard")
@login_required
def dashboard():
    added = update_database()

    total       = Threat.query.count()
    critical    = Threat.query.filter_by(severity="Critical").count()
    high        = Threat.query.filter_by(severity="High").count()
    medium      = Threat.query.filter_by(severity="Medium").count()
    open_count  = Threat.query.filter_by(status="Open").count()
    recent_logs = Threat.query.order_by(Threat.timestamp.desc()).limit(10).all()

    # Threat type distribution for chart
    threat_counts = {}
    for t in Threat.query.all():
        threat_counts[t.threat_type] = threat_counts.get(t.threat_type, 0) + 1

    return render_template(
        "index.html",
        total_logs=total,
        critical_alerts=critical,
        high_alerts=high,
        medium_alerts=medium,
        open_alerts=open_count,
        recent_logs=recent_logs,
        threat_counts=threat_counts,
        new_threats=added,
        page_title="Dashboard",
    )

# ==============================
# LOGS
# ==============================

@app.route("/logs")
@login_required
def logs():
    page      = request.args.get("page", 1, type=int)
    severity  = request.args.get("severity", "")
    search    = request.args.get("search", "")
    per_page  = 20

    query = Threat.query
    if severity:
        query = query.filter_by(severity=severity)
    if search:
        query = query.filter(
            db.or_(
                Threat.threat_type.ilike(f"%{search}%"),
                Threat.source_ip.ilike(f"%{search}%"),
            )
        )
    pagination = query.order_by(Threat.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template(
        "logs.html",
        logs=pagination.items,
        pagination=pagination,
        severity=severity,
        search=search,
        page_title="Threat Logs",
    )

# ==============================
# ALERTS
# ==============================

@app.route("/alerts")
@login_required
def alerts():
    alerts_list = Threat.query.filter(
        Threat.severity.in_(["Critical", "High"]),
        Threat.status == "Open"
    ).order_by(Threat.timestamp.desc()).all()

    return render_template(
        "alerts.html",
        alerts=alerts_list,
        page_title="Active Alerts",
    )


@app.route("/alerts/acknowledge/<int:alert_id>", methods=["POST"])
@login_required
def acknowledge_alert(alert_id):
    alert = Threat.query.get_or_404(alert_id)
    alert.status = "Acknowledged"
    db.session.commit()
    log_action(f"Acknowledged alert #{alert_id} ({alert.threat_type})")
    return jsonify({"success": True, "status": "Acknowledged"})


@app.route("/alerts/resolve/<int:alert_id>", methods=["POST"])
@login_required
def resolve_alert(alert_id):
    alert = Threat.query.get_or_404(alert_id)
    alert.status = "Resolved"
    db.session.commit()
    log_action(f"Resolved alert #{alert_id} ({alert.threat_type})")
    return jsonify({"success": True, "status": "Resolved"})


@app.route("/threats/delete/<int:threat_id>", methods=["POST"])
@login_required
def delete_threat(threat_id):
    threat = Threat.query.get_or_404(threat_id)
    log_action(f"Deleted threat #{threat_id} ({threat.threat_type})")
    db.session.delete(threat)
    db.session.commit()
    return jsonify({"success": True})


@app.route("/threats/clear_all", methods=["POST"])
@login_required
def clear_all_threats():
    count = Threat.query.count()
    Threat.query.delete()
    db.session.commit()
    log_action(f"Cleared all {count} threat records")
    return jsonify({"success": True, "deleted": count})

# ==============================
# REPORTS
# ==============================

@app.route("/reports")
@login_required
def reports():
    all_threats = Threat.query.order_by(Threat.timestamp.desc()).all()

    severity_stats = {
        "Critical": Threat.query.filter_by(severity="Critical").count(),
        "High":     Threat.query.filter_by(severity="High").count(),
        "Medium":   Threat.query.filter_by(severity="Medium").count(),
        "Low":      Threat.query.filter_by(severity="Low").count(),
    }
    status_stats = {
        "Open":         Threat.query.filter_by(status="Open").count(),
        "Acknowledged": Threat.query.filter_by(status="Acknowledged").count(),
        "Resolved":     Threat.query.filter_by(status="Resolved").count(),
    }

    return render_template(
        "reports.html",
        reports=all_threats,
        severity_stats=severity_stats,
        status_stats=status_stats,
        page_title="Reports",
    )

# ==============================
# PDF DOWNLOAD
# ==============================

@app.route("/download_report")
@login_required
def download_report():
    threats = Threat.query.order_by(Threat.timestamp.desc()).all()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=0.75*inch, rightMargin=0.75*inch,
        topMargin=1*inch, bottomMargin=0.75*inch
    )

    styles   = getSampleStyleSheet()
    elements = []

    # ---- Title ----
    title_style = ParagraphStyle(
        "Title", parent=styles["Title"],
        fontSize=22, textColor=colors.HexColor("#0ea5e9"),
        spaceAfter=4, alignment=TA_CENTER
    )
    sub_style = ParagraphStyle(
        "Sub", parent=styles["Normal"],
        fontSize=10, textColor=colors.HexColor("#64748b"),
        alignment=TA_CENTER, spaceAfter=16
    )

    elements.append(Paragraph("Mini SIEM — Security Incident Report", title_style))
    elements.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  "
        f"Analyst: {session.get('username', 'admin')}  |  "
        f"Total Threats: {len(threats)}",
        sub_style
    ))
    elements.append(HRFlowable(width="100%", thickness=1,
                                color=colors.HexColor("#0ea5e9"), spaceAfter=14))

    # ---- Summary ----
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for t in threats:
        sev_counts[t.severity] = sev_counts.get(t.severity, 0) + 1

    summary_data = [["Severity", "Count"]]
    sev_colors   = {
        "Critical": colors.HexColor("#ef4444"),
        "High":     colors.HexColor("#f97316"),
        "Medium":   colors.HexColor("#eab308"),
        "Low":      colors.HexColor("#22c55e"),
    }
    for sev, cnt in sev_counts.items():
        summary_data.append([sev, str(cnt)])

    summary_table = Table(summary_data, colWidths=[2.5*inch, 1.5*inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.HexColor("#38bdf8")),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 10),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
            [colors.HexColor("#1e293b"), colors.HexColor("#0f172a")]),
        ("TEXTCOLOR",   (0, 1), (-1, -1), colors.white),
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#334155")),
        ("ROWPADDING",  (0, 0), (-1, -1), 6),
    ]))

    elements.append(Paragraph("Severity Summary", ParagraphStyle(
        "H2", parent=styles["Heading2"],
        fontSize=13, textColor=colors.HexColor("#38bdf8"), spaceAfter=8
    )))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))

    # ---- Threats Table ----
    elements.append(Paragraph("Detected Threats", ParagraphStyle(
        "H2", parent=styles["Heading2"],
        fontSize=13, textColor=colors.HexColor("#38bdf8"), spaceAfter=8
    )))

    header = [["#", "Threat Type", "Severity", "Source IP", "Status", "Timestamp"]]
    rows   = []
    for t in threats:
        rows.append([
            str(t.id), t.threat_type, t.severity,
            t.source_ip, t.status,
            t.timestamp.strftime("%Y-%m-%d %H:%M")
        ])

    table_data = header + rows
    col_widths = [0.4*inch, 1.8*inch, 0.9*inch, 1.1*inch, 1.1*inch, 1.5*inch]
    main_table = Table(table_data, colWidths=col_widths, repeatRows=1)

    row_styles = [
        ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR",    (0, 0), (-1, 0), colors.HexColor("#38bdf8")),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 8),
        ("TEXTCOLOR",    (0, 1), (-1, -1), colors.white),
        ("ALIGN",        (0, 0), (-1, -1), "LEFT"),
        ("GRID",         (0, 0), (-1, -1), 0.4, colors.HexColor("#334155")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
            [colors.HexColor("#1e293b"), colors.HexColor("#0f172a")]),
        ("ROWPADDING",   (0, 0), (-1, -1), 5),
    ]
    for i, t in enumerate(threats, start=1):
        clr = sev_colors.get(t.severity, colors.white)
        row_styles.append(("TEXTCOLOR", (2, i), (2, i), clr))
        row_styles.append(("FONTNAME",  (2, i), (2, i), "Helvetica-Bold"))

    main_table.setStyle(TableStyle(row_styles))
    elements.append(main_table)

    doc.build(elements)
    buf.seek(0)

    log_action("Downloaded PDF security report")
    return send_file(
        buf,
        as_attachment=True,
        download_name=f"SIEM_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
        mimetype="application/pdf"
    )

# ==============================
# SETTINGS
# ==============================

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(30).all()

    if request.method == "POST":
        action = request.form.get("action")
        if action == "clear_db":
            count = Threat.query.count()
            Threat.query.delete()
            db.session.commit()
            log_action(f"Cleared database ({count} records)")
            flash(f"Database cleared. {count} records removed.", "success")
        elif action == "generate_logs":
            from generator import generate_batch
            n = generate_batch(20)
            added = update_database()
            log_action(f"Manually generated {n} log lines → {added} new threats")
            flash(f"Generated {n} log lines. {added} new threats detected.", "success")
        return redirect(url_for("settings"))

    return render_template(
        "settings.html",
        audit_logs=audit_logs,
        threat_signatures=THREAT_SIGNATURES,
        page_title="Settings",
    )

# ==============================
# API ENDPOINTS (JSON)
# ==============================

@app.route("/api/stats")
@login_required
def api_stats():
    update_database()
    return jsonify({
        "total":    Threat.query.count(),
        "critical": Threat.query.filter_by(severity="Critical").count(),
        "high":     Threat.query.filter_by(severity="High").count(),
        "medium":   Threat.query.filter_by(severity="Medium").count(),
        "open":     Threat.query.filter_by(status="Open").count(),
    })


@app.route("/api/recent_threats")
@login_required
def api_recent_threats():
    threats = Threat.query.order_by(Threat.timestamp.desc()).limit(10).all()
    return jsonify([t.to_dict() for t in threats])


@app.route("/api/threat_distribution")
@login_required
def api_threat_distribution():
    result = {}
    for t in Threat.query.all():
        result[t.threat_type] = result.get(t.threat_type, 0) + 1
    return jsonify(result)

# ==============================
# RUN
# ==============================

# ==============================
# JINJA2 GLOBALS
# ==============================

app.jinja_env.globals['enumerate'] = enumerate

# ==============================
# RUN
# ==============================

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
