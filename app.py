import os
import io
import json
import hashlib
from datetime import datetime
from urllib.parse import quote_plus
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Image & Metadata Processing
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

# ReportLab imports for structured PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# ------------------------------------------------------------------------------
# App & Database Configuration
# ------------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "super_secret_insureguard_key")
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload limit

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

MYSQL_USER = os.environ.get("MYSQL_USER", "root")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "password")
MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
MYSQL_PORT = os.environ.get("MYSQL_PORT", "3306")
MYSQL_DB = os.environ.get("MYSQL_DB", "insureguard_db")

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 
    f'mysql+pymysql://{MYSQL_USER}:atharv012@{MYSQL_HOST}:3306/{MYSQL_DB}'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ------------------------------------------------------------------------------
# Database Models (With Network Graph & Evidence Metadata)
# ------------------------------------------------------------------------------
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='CUSTOMER', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Claim(db.Model):
    __tablename__ = 'claims'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username = db.Column(db.String(150), nullable=True)
    
    # Claim Details
    policy_type = db.Column(db.String(100), nullable=True)
    vehicle_category = db.Column(db.String(100), nullable=True)
    incident_severity = db.Column(db.String(100), nullable=True)
    authorities_contacted = db.Column(db.String(100), nullable=True)
    claim_amount = db.Column(db.Float, default=0.0)
    policy_age_months = db.Column(db.Integer, default=12)
    incident_date = db.Column(db.String(50), nullable=True)
    incident_location = db.Column(db.String(150), nullable=True)

    # Entity Resolution / Network Graph Identifiers
    contact_phone = db.Column(db.String(50), nullable=True)
    repair_shop_id = db.Column(db.String(100), nullable=True)

    # Forensic File Metadata
    file_hash = db.Column(db.String(64), nullable=True)  # SHA-256 Hash
    exif_flagged = db.Column(db.Boolean, default=False)
    duplicate_image_detected = db.Column(db.Boolean, default=False)
    
    # Risk Engine Outputs
    risk_score = db.Column(db.Float, default=0.0)
    prediction = db.Column(db.Integer, default=0) # 0 = Legitimate, 1 = Flagged Fraud
    is_fraud = db.Column(db.Boolean, default=False)
    risk_factors = db.Column(db.Text, nullable=True) # JSON array string of risk drivers
    
    # Case Management Workflow & Audit Trail
    status = db.Column(db.String(50), default='ASSESSED') # ASSESSED, PENDING_REVIEW, UNDER_INVESTIGATION, APPROVED, REJECTED
    investigation_requested = db.Column(db.Boolean, default=False)
    investigator_notes = db.Column(db.Text, nullable=True)
    audit_trail = db.Column(db.Text, nullable=True) # JSON array string of status changes
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ------------------------------------------------------------------------------
# Form Options
# ------------------------------------------------------------------------------
OPTIONS = {
    'policy_type': ['Auto Comprehensive', 'Auto Collision', 'Property Loss', 'Commercial Liability', 'Weather Storm Damage'],
    'vehicle_category': ['Sedan', 'SUV / Truck', 'Luxury / Sports Vehicle', 'Commercial Van / Fleet'],
    'incident_severity': ['Minor Damage', 'Major Damage', 'Total Loss'],
    'authorities_contacted': ['Police', 'Fire Department', 'Ambulance', 'None']
}

# ------------------------------------------------------------------------------
# Forensics & Real-World Feature Helpers
# ------------------------------------------------------------------------------
def get_file_hash(file_bytes):
    """Generates SHA-256 checksum for image duplicate detection."""
    return hashlib.sha256(file_bytes).hexdigest()

def extract_image_forensics(file_storage):
    """Extracts EXIF metadata to flag missing or inconsistent timestamps/GPS."""
    exif_flagged = False
    details = []
    try:
        img = Image.open(file_storage)
        exif_data = img._getexif()
        if not exif_data:
            exif_flagged = True
            details.append("Image lacks camera EXIF metadata (Possible screenshot or scrubbed photo).")
        else:
            tags = {TAGS.get(key, key): val for key, val in exif_data.items()}
            if 'DateTimeOriginal' not in tags and 'DateTime' not in tags:
                exif_flagged = True
                details.append("Missing original capture timestamp in EXIF headers.")
    except Exception:
        exif_flagged = True
        details.append("Unable to parse image EXIF data.")
    return exif_flagged, details

def check_network_syndicate(phone, repair_shop, current_user_id):
    """Entity resolution: Flags shared contact details across different accounts."""
    flags = []
    if phone:
        match_phone = Claim.query.filter(Claim.contact_phone == phone, Claim.user_id != current_user_id).first()
        if match_phone:
            flags.append(f"Phone number ({phone}) is linked to another claimant account (Claim #{match_phone.id}).")
    if repair_shop:
        match_shop_count = Claim.query.filter(Claim.repair_shop_id == repair_shop, Claim.prediction == 1).count()
        if match_shop_count >= 2:
            flags.append(f"Repair Shop ID ({repair_shop}) is associated with {match_shop_count} previous fraud flags.")
    return flags

def validate_weather_anomaly(policy_type, incident_date):
    """Geolocation/Weather validation simulation."""
    if policy_type == "Weather Storm Damage" and incident_date:
        # Example validation logic for historical weather check
        if "2026" in incident_date and "-02-" in incident_date:
            return True, "Historical meteorological data shows no severe storm activity reported on this date."
    return False, ""

# ------------------------------------------------------------------------------
# Unified Real-World AI Risk Engine
# ------------------------------------------------------------------------------
def evaluate_realworld_claim_risk(data, file_bytes, file_storage, current_user_id):
    claim_amount = float(data.get('claim_amount', 0.0))
    severity = data.get('incident_severity', '')
    policy_type = data.get('policy_type', '')
    policy_age = int(data.get('policy_age_months', 12))
    authorities = data.get('authorities_contacted', 'None')
    phone = data.get('contact_phone', '')
    repair_shop = data.get('repair_shop_id', '')
    incident_date = data.get('incident_date', '')

    score = 0.10
    factors = []

    # 1. XGBoost/ML Scoring Simulation (Core Metadata)
    if claim_amount > 25000:
        score += 0.30
        factors.append({"factor": "High Exposure Value", "impact": "+30%", "detail": f"Claim (${claim_amount:,.2f}) exceeds standard tier threshold."})
    elif claim_amount > 10000:
        score += 0.15
        factors.append({"factor": "Elevated Value", "impact": "+15%", "detail": f"Claim (${claim_amount:,.2f}) is above average."})

    if severity in ['Major Damage', 'Total Loss']:
        score += 0.20
        factors.append({"factor": "High Severity", "impact": "+20%", "detail": f"Severity logged as {severity}."})

    if policy_age < 3:
        score += 0.25
        factors.append({"factor": "Rapid Inception Claim", "impact": "+25%", "detail": f"Policy opened only {policy_age} month(s) ago."})

    if authorities == 'None' and severity != 'Minor Damage':
        score += 0.15
        factors.append({"factor": "Unreported Major Loss", "impact": "+15%", "detail": "No official authorities contacted."})

    # 2. File Forensics & Duplicate Hash Check
    file_hash = None
    duplicate_found = False
    exif_flagged = False

    if file_bytes:
        file_hash = get_file_hash(file_bytes)
        existing_file = Claim.query.filter_by(file_hash=file_hash).first()
        if existing_file:
            duplicate_found = True
            score += 0.40
            factors.append({"factor": "Duplicate File Detected", "impact": "+40%", "detail": f"Identical image/document previously submitted in Claim #{existing_file.id}."})

    if file_storage and file_storage.filename != '':
        exif_flagged, exif_details = extract_image_forensics(file_storage)
        if exif_flagged:
            score += 0.15
            for detail in exif_details:
                factors.append({"factor": "Forensic EXIF Anomaly", "impact": "+15%", "detail": detail})

    # 3. Entity Resolution & Network Graph
    syndicate_flags = check_network_syndicate(phone, repair_shop, current_user_id)
    for flag in syndicate_flags:
        score += 0.25
        factors.append({"factor": "Syndicate / Graph Risk Flag", "impact": "+25%", "detail": flag})

    # 4. Geolocation & Weather Anomaly
    weather_invalid, weather_msg = validate_weather_anomaly(policy_type, incident_date)
    if weather_invalid:
        score += 0.30
        factors.append({"factor": "Weather Verification Mismatch", "impact": "+30%", "detail": weather_msg})

    final_score = min(round(score, 4), 0.99)
    prediction = 1 if final_score >= 0.50 else 0

    return {
        'risk_score': final_score,
        'prediction': prediction,
        'risk_factors': json.dumps(factors),
        'file_hash': file_hash,
        'duplicate_found': duplicate_found,
        'exif_flagged': exif_flagged
    }

# ------------------------------------------------------------------------------
# DB Initialization
# ------------------------------------------------------------------------------
with app.app_context():
    db.create_all()
    
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            password=generate_password_hash('admin123'),
            role='ADMIN'
        )
        db.session.add(admin)
        db.session.commit()

# ------------------------------------------------------------------------------
# Authentication Routes
# ------------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'CUSTOMER')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already registered. Please login.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html', is_admin=False)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username, role='ADMIN').first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Admin portal authentication successful.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.', 'danger')

    return render_template('login.html', is_admin=True)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('Please login to edit your profile.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get_or_404(session['user_id'])

    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = request.form.get('password')

        if new_username and new_username != user.username:
            existing = User.query.filter_by(username=new_username).first()
            if existing:
                flash('Username already taken.', 'danger')
                return redirect(url_for('profile'))
            user.username = new_username
            session['username'] = new_username

        if new_password:
            user.password = generate_password_hash(new_password)

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

# ------------------------------------------------------------------------------
# Dashboard & Assessment Routes
# ------------------------------------------------------------------------------
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login to access your profile dashboard.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get_or_404(session['user_id'])
    history = Claim.query.filter_by(user_id=user.id).order_by(Claim.created_at.desc()).all()

    total_claims = len(history)
    flagged_claims = sum(1 for c in history if c.prediction == 1)
    legitimate_claims = total_claims - flagged_claims
    avg_risk = (sum(c.risk_score for c in history) / total_claims * 100) if total_claims > 0 else 0

    chart_labels = [c.created_at.strftime('%m/%d %H:%M') for c in reversed(history)]
    chart_scores = [round(c.risk_score * 100, 2) for c in reversed(history)]

    return render_template(
        'dashboard.html',
        user=user,
        history=history,
        total_claims=total_claims,
        flagged_claims=flagged_claims,
        legitimate_claims=legitimate_claims,
        avg_risk=avg_risk,
        chart_labels=chart_labels,
        chart_scores=chart_scores
    )

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if 'user_id' not in session:
        flash('Please log in to run an assessment.', 'danger')
        return redirect(url_for('login'))

    result = None
    claim = None

    if request.method == 'POST':
        uploaded_file = request.files.get('evidence_file')
        file_bytes = uploaded_file.read() if uploaded_file and uploaded_file.filename != '' else None
        
        if uploaded_file and file_bytes:
            uploaded_file.seek(0) # Reset stream for PIL reading

        data = {
            'policy_type': request.form.get('policy_type'),
            'vehicle_category': request.form.get('vehicle_category'),
            'incident_severity': request.form.get('incident_severity'),
            'authorities_contacted': request.form.get('authorities_contacted'),
            'claim_amount': request.form.get('claim_amount', 0.0),
            'policy_age_months': request.form.get('policy_age_months', 12),
            'contact_phone': request.form.get('contact_phone', ''),
            'repair_shop_id': request.form.get('repair_shop_id', ''),
            'incident_date': request.form.get('incident_date', '')
        }

        # Multi-modal Real-World Assessment
        analysis = evaluate_realworld_claim_risk(data, file_bytes, uploaded_file, session.get('user_id'))

        initial_audit = json.dumps([{
            "timestamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            "event": "Claim Assessed by Real-World Risk Engine",
            "score": f"{analysis['risk_score']*100:.1f}%"
        }])

        claim = Claim(
            user_id=session.get('user_id'),
            username=session.get('username', 'Customer'),
            policy_type=data['policy_type'],
            vehicle_category=data['vehicle_category'],
            incident_severity=data['incident_severity'],
            authorities_contacted=data['authorities_contacted'],
            claim_amount=float(data['claim_amount']),
            policy_age_months=int(data['policy_age_months']),
            contact_phone=data['contact_phone'],
            repair_shop_id=data['repair_shop_id'],
            incident_date=data['incident_date'],
            file_hash=analysis['file_hash'],
            duplicate_image_detected=analysis['duplicate_found'],
            exif_flagged=analysis['exif_flagged'],
            risk_score=analysis['risk_score'],
            prediction=analysis['prediction'],
            is_fraud=(analysis['prediction'] == 1),
            risk_factors=analysis['risk_factors'],
            audit_trail=initial_audit,
            status='ASSESSED'
        )

        db.session.add(claim)
        db.session.commit()

        # Simulated Real-World Email/Webhook Alert Trigger
        if claim.prediction == 1:
            print(f"[NOTIFICATION DISPATCH] Alert sent to SIU Team: High Risk Claim ID #{claim.id} logged with score {claim.risk_score*100:.1f}%")

        risk_factors_list = []
        if claim.risk_factors:
            try:
                risk_factors_list = json.loads(claim.risk_factors)
            except Exception:
                risk_factors_list = []

        result = {
            'prediction': claim.prediction,
            'risk_score': claim.risk_score,
            'risk_factors': risk_factors_list
        }

    return render_template("predict.html", options=OPTIONS, result=result, claim=claim)

# ------------------------------------------------------------------------------
# Investigation & Workbench Workflow
# ------------------------------------------------------------------------------
@app.route('/claim/<int:claim_id>/apply_investigation', methods=['POST'])
def apply_investigation(claim_id):
    if 'user_id' not in session:
        flash('Please log in to apply for investigation.', 'danger')
        return redirect(url_for('login'))

    claim = Claim.query.get_or_404(claim_id)
    
    if claim.user_id != session.get('user_id') and session.get('role') != 'ADMIN':
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('dashboard'))

    claim.investigation_requested = True
    claim.status = 'PENDING_REVIEW'

    # Append to Audit Trail
    audit = json.loads(claim.audit_trail) if claim.audit_trail else []
    audit.append({
        "timestamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        "event": "Manual Investigation Requested by Claimant"
    })
    claim.audit_trail = json.dumps(audit)

    db.session.commit()
    flash('Investigation request submitted successfully. An adjuster will review your case file.', 'success')
    return redirect(url_for('investigate_case', claim_id=claim.id))

@app.route('/claim/<int:claim_id>/investigate', methods=['GET', 'POST'])
def investigate_case(claim_id):
    if request.method == 'POST':
        # The investigation page form posts to its own URL; reuse the admin status-update logic
        return update_claim_status(claim_id)

    if 'user_id' not in session:
        flash('Please log in to view case details.', 'danger')
        return redirect(url_for('login'))

    claim = Claim.query.get_or_404(claim_id)
    
    risk_factors = []
    if claim.risk_factors:
        try:
            risk_factors = json.loads(claim.risk_factors)
        except Exception:
            risk_factors = []

    audit_trail = []
    if claim.audit_trail:
        try:
            audit_trail = json.loads(claim.audit_trail)
        except Exception:
            audit_trail = []

    return render_template('investigate_case.html', claim=claim, risk_factors=risk_factors, audit_trail=audit_trail)

@app.route('/claim/<int:claim_id>/update_status', methods=['POST'])
def update_claim_status(claim_id):
    if 'user_id' not in session or session.get('role') != 'ADMIN':
        flash('Admin authorization required to update case decisions.', 'danger')
        return redirect(url_for('login'))

    claim = Claim.query.get_or_404(claim_id)
    new_status = request.form.get('status', claim.status)
    claim.investigator_notes = request.form.get('investigator_notes', claim.investigator_notes)

    if new_status != claim.status:
        audit = json.loads(claim.audit_trail) if claim.audit_trail else []
        audit.append({
            "timestamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            "event": f"Status updated to '{new_status}' by Admin ({session.get('username')})"
        })
        claim.audit_trail = json.dumps(audit)
        claim.status = new_status

    db.session.commit()
    flash('Investigation workbench record updated.', 'success')
    return redirect(url_for('investigate_case', claim_id=claim.id))

# ------------------------------------------------------------------------------
# Admin Portal
# ------------------------------------------------------------------------------
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'ADMIN':
        flash('Admin authorization required to access this page.', 'danger')
        return redirect(url_for('admin_login'))

    users = User.query.all()
    all_claims = Claim.query.order_by(Claim.created_at.desc()).all()

    total_users = len(users)
    total_claims = len(all_claims)
    total_flagged = sum(1 for c in all_claims if c.prediction == 1)
    total_legitimate = total_claims - total_flagged
    avg_system_risk = (sum(c.risk_score for c in all_claims) / total_claims * 100) if total_claims > 0 else 0

    return render_template(
        'admin.html',
        users=users,
        claims=all_claims,
        total_users=total_users,
        total_claims=total_claims,
        total_flagged=total_flagged,
        total_legitimate=total_legitimate,
        avg_system_risk=avg_system_risk
    )

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'ADMIN':
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('admin_dashboard'))

    user = User.query.get_or_404(user_id)
    if user.role == 'ADMIN':
        flash('Cannot delete an admin account.', 'danger')
        return redirect(url_for('admin_dashboard'))

    Claim.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()

    flash(f'User "{user.username}" and associated records removed successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

# ------------------------------------------------------------------------------
# Fraud Ring Network Graph (feeds network_graph.html)
# ------------------------------------------------------------------------------
@app.route('/admin/network')
def network_graph():
    if 'user_id' not in session or session.get('role') != 'ADMIN':
        flash('Admin authorization required to access this page.', 'danger')
        return redirect(url_for('admin_login'))

    nodes, edges, seen = [], [], set()

    def add_node(node_id, label, color=None):
        if node_id not in seen:
            seen.add(node_id)
            node = {"id": node_id, "label": label}
            if color:
                node["color"] = {"background": color[0], "border": color[1]}
            nodes.append(node)

    for c in Claim.query.all():
        claim_node = f"claim-{c.id}"
        flagged = c.prediction == 1
        add_node(claim_node, f"Claim #{c.id}", ("#4c0519", "#fb7185") if flagged else None)
        if c.username:
            add_node(f"user-{c.user_id}", c.username)
            edges.append({"from": f"user-{c.user_id}", "to": claim_node, "label": "filed"})
        if c.contact_phone:
            add_node(f"phone-{c.contact_phone}", c.contact_phone, ("#083344", "#22d3ee"))
            edges.append({"from": claim_node, "to": f"phone-{c.contact_phone}", "label": "phone"})
        if c.repair_shop_id:
            add_node(f"shop-{c.repair_shop_id}", c.repair_shop_id, ("#422006", "#f59e0b"))
            edges.append({"from": claim_node, "to": f"shop-{c.repair_shop_id}", "label": "repaired at"})

    return render_template('network_graph.html', graph_data={"nodes": nodes, "edges": edges})

# ------------------------------------------------------------------------------
# Custom Error Pages
# ------------------------------------------------------------------------------
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(413)
def file_too_large(e):
    flash('That file is too large. The maximum upload size is 16 MB.', 'danger')
    return redirect(url_for('predict'))

@app.errorhandler(500)
def server_error(e):
    db.session.rollback()  # leave the DB session clean after a failed request
    return render_template('500.html'), 500

# ------------------------------------------------------------------------------
# Report Export
# ------------------------------------------------------------------------------
@app.route('/download_report/<int:claim_id>')
def download_report(claim_id):
    claim = Claim.query.get_or_404(claim_id)

    if claim.prediction == 1 and claim.status != 'APPROVED' and session.get('role') != 'ADMIN':
        flash('PDF Report Generation is restricted for claims flagged with elevated risk until manual investigation approval is granted.', 'danger')
        return redirect(url_for('predict'))

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=20, textColor=colors.HexColor('#0f172a'), spaceAfter=4)
    subtitle_style = ParagraphStyle('DocSub', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#64748b'), spaceAfter=12)
    section_heading = ParagraphStyle('SectionHead', parent=styles['Heading2'], fontSize=12, textColor=colors.HexColor('#1e293b'), spaceBefore=10, spaceAfter=6)

    elements = []

    elements.append(Paragraph("InsureGuard Risk Assessment Report", title_style))
    elements.append(Paragraph(f"Generated: {claim.created_at.strftime('%Y-%m-%d %H:%M:%S')} UTC | Report ID: IG-CLM-{claim.id:05d}", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e1'), spaceAfter=12))

    is_fraud = "HIGH FRAUD RISK" if claim.prediction == 1 else "LEGITIMATE CLAIM"
    status_color = colors.HexColor('#dc2626') if claim.prediction == 1 else colors.HexColor('#16a34a')

    summary_data = [
        [Paragraph("<b>Risk Evaluation Summary</b>", styles['Normal']), ""],
        ["Risk Assessment:", Paragraph(f"<b><font color='{status_color.hexval()}'>{is_fraud}</font></b>", styles['Normal'])],
        ["Risk Score:", f"{(claim.risk_score * 100):.2f}%"],
        ["Investigation Status:", claim.status],
        ["User:", claim.username if claim.username else f"User ID: {claim.user_id}"]
    ]

    summary_table = Table(summary_data, colWidths=[180, 360])
    summary_table.setStyle(TableStyle([
        ('SPAN', (0, 0), (1, 0)),
        ('BACKGROUND', (0, 0), (1, 0), colors.HexColor('#f8fafc')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 10))

    elements.append(Paragraph("Claim Metadata & Forensics", section_heading))
    table_data = [["Attribute", "Value"]]
    features = {
        "Policy Type": claim.policy_type or 'N/A',
        "Vehicle Category": claim.vehicle_category or 'N/A',
        "Claim Amount": f"${claim.claim_amount:,.2f}" if claim.claim_amount else "$0.00",
        "Policy Age": f"{claim.policy_age_months} Month(s)",
        "Incident Severity": claim.incident_severity or 'N/A',
        "Authorities Contacted": claim.authorities_contacted or 'N/A',
        "Contact Phone": claim.contact_phone or 'N/A',
        "Repair Shop ID": claim.repair_shop_id or 'N/A',
        "File Checksum Hash": claim.file_hash[:16] + "..." if claim.file_hash else "None Provided"
    }

    for key, val in features.items():
        table_data.append([key, str(val)])

    details_table = Table(table_data, colWidths=[200, 340])
    details_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
    ]))
    elements.append(details_table)

    if claim.investigator_notes:
        elements.append(Spacer(1, 10))
        elements.append(Paragraph("Investigator Findings", section_heading))
        notes_p = Paragraph(claim.investigator_notes, styles['Normal'])
        notes_table = Table([[notes_p]], colWidths=[540])
        notes_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f5f9')),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ]))
        elements.append(notes_table)

    doc.build(elements)
    buffer.seek(0)

    return send_file(
        buffer, as_attachment=True, download_name=f"InsureGuard_Report_{claim_id}.pdf", mimetype='application/pdf'
    )

if __name__ == '__main__':
    app.run(debug=True, port=5000)