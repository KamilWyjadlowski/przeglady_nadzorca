from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    g,
    Response,
)
import calendar
import smtplib
import json
import csv
import io
import os
import re
import secrets
from datetime import date, datetime, timedelta
from functools import wraps
from math import ceil
from typing import List, Dict, Optional
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Date,
    DateTime,
    Text,
    JSON,
    ForeignKey,
    func,
    text,
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship

app = Flask(__name__)
secret_from_env = os.getenv("SECRET_KEY")
app.config["SECRET_KEY"] = secret_from_env or secrets.token_hex(32)
APP_VERSION = "Alpha 1.1"

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "przeglady")
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "nadzorca.przegladow@gmail.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)
SMTP_TLS = os.getenv("SMTP_TLS", "true").lower() in ("1", "true", "yes")
if DB_HOST.startswith("/cloudsql/"):
    DB_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@/{DB_NAME}?unix_socket={DB_HOST}"
    engine = create_engine(DB_URL, pool_pre_ping=True, echo=False, future=True)
else:
    DB_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    engine = create_engine(DB_URL, pool_pre_ping=True, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="user")
    email = Column(String(255))


class Inspection(Base):
    __tablename__ = "inspections"
    id = Column(Integer, primary_key=True)
    nazwa = Column(String(255), nullable=False)
    nieruchomosc = Column(String(255), nullable=False)
    property_id = Column(String(32))
    ostatnia_data = Column(Date, nullable=False)
    czestotliwosc_miesiace = Column(Integer, nullable=False)
    kolejna_data = Column(Date, nullable=False)
    status = Column(String(32), nullable=False)
    opis = Column(Text)
    firma = Column(String(255))
    telefon = Column(String(64))
    email = Column(String(255))
    segment = Column(String(32))
    owner = Column(String(100), nullable=False)


class PropertyAccess(Base):
    __tablename__ = "property_access"
    id = Column(Integer, primary_key=True)
    nieruchomosc = Column(String(255), nullable=False)
    username = Column(String(100), nullable=False)


class Property(Base):
    __tablename__ = "properties"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    property_id = Column(String(32))
    segment = Column(String(32))


class AppSetting(Base):
    __tablename__ = "app_settings"
    id = Column(Integer, primary_key=True)
    key = Column(String(100), unique=True, nullable=False)
    value = Column(Text)


class Audit(Base):
    __tablename__ = "audit"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, nullable=False)
    action = Column(String(64), nullable=False)
    user = Column(String(100))
    details = Column(JSON)


class InspectionOccurrence(Base):
    __tablename__ = "inspection_occurrences"
    id = Column(Integer, primary_key=True)
    inspection_id = Column(Integer, ForeignKey("inspections.id"), nullable=False)
    due_date = Column(Date, nullable=False)
    done_date = Column(Date)
    status = Column(String(32), nullable=False, default="planned")
    note = Column(Text)
    performed_by = Column(String(100))
    created_at = Column(DateTime, server_default=func.now())
    inspection = relationship("Inspection", backref="occurrences")


class CompanyContact(Base):
    __tablename__ = "company_contacts"
    id = Column(Integer, primary_key=True)
    company_name = Column(String(255), nullable=False)
    contact_name = Column(String(255))
    phone = Column(String(64))
    email = Column(String(255))


class CompanyContactAssignment(Base):
    __tablename__ = "company_contact_assignments"
    id = Column(Integer, primary_key=True)
    contact_id = Column(Integer, ForeignKey("company_contacts.id"), nullable=False)
    property_name = Column(String(255), nullable=False)
    scope = Column(String(255))
    contact = relationship("CompanyContact", backref="assignments")


def parse_date(s: str) -> date:
    s = s.strip()

    if "." in s:
        parts = s.split(".")
        if len(parts) == 3:
            d, m, y = parts
            try:
                return date(int(y), int(m), int(d))
            except ValueError:
                pass

    try:
        return date.fromisoformat(s)
    except ValueError:
        raise ValueError(
            f"Nieprawidłowy format daty: '{s}'. Użyj RRRR-MM-DD lub DD.MM.RRRR."
        )


def normalize_property_name(raw: str) -> str:
    return " ".join(p.capitalize() for p in raw.strip().split())


@app.template_filter("format_property")
def format_property(raw: str) -> str:
    if raw is None:
        return ""
    s = " ".join(str(raw).strip().split())
    if not s:
        return ""

    city = ""
    rest = ""
    if "," in s:
        city, rest = [p.strip() for p in s.split(",", 1)]
    else:
        rest = s

    if not city:
        match = re.search(r"\bul\.?\b", s, flags=re.IGNORECASE)
        if match:
            city = s[: match.start()].strip().rstrip(",")
            rest = s[match.end() :].strip()
        else:
            tokens = s.split()
            if len(tokens) == 1:
                return tokens[0]
            city = tokens[0]
            rest = " ".join(tokens[1:])

    rest = re.sub(r"^ul\.?\s+", "", rest, flags=re.IGNORECASE).strip()
    if not rest:
        return city or s

    tokens = rest.split()
    number = ""
    street = rest
    last = tokens[-1]
    if re.match(r"^\d+[A-Za-z]?(?:/\d+[A-Za-z]?)?$", last):
        number = last
        street = " ".join(tokens[:-1]).strip()

    if not city:
        return s
    if not street:
        return city
    if number:
        return f"{city}, ul. {street} {number}"
    return f"{city}, ul. {street}"


def add_months(d: date, months: int) -> date:
    year = d.year + (d.month - 1 + months) // 12
    month = (d.month - 1 + months) % 12 + 1
    day = min(d.day, calendar.monthrange(year, month)[1])
    return date(year, month, day)


def clean_empty_notes(text: str) -> str:
    text = text.strip()
    return text if text else "Brak uwag"


def export_filename(ext: str) -> str:
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    return f"przeglady_{stamp}.{ext}"


def normalize_phone(phone: str) -> str:
    cleaned = re.sub(r"[\s\-()]", "", phone)
    if cleaned.startswith("+"):
        digits = cleaned[1:]
        prefix = "+"
    else:
        digits = cleaned
        prefix = ""
    if not digits.isdigit() or len(digits) < 7:
        raise ValueError("Nieprawidłowy numer telefonu.")
    return prefix + digits


def ensure_property_ids(inspections: List[Dict]) -> tuple[bool, Dict[str, str], int]:
    mapping: Dict[str, str] = {}
    max_num = 0
    pat = re.compile(r"^P(\\d+)$")

    for ins in inspections:
        pid = ins.get("property_id", "")
        if pid:
            mapping.setdefault(ins.get("nieruchomosc"), pid)
            m = pat.match(pid)
            if m:
                max_num = max(max_num, int(m.group(1)))

    changed = False
    for ins in inspections:
        if not ins.get("property_id"):
            max_num += 1
            pid = f"P{max_num:04d}"
            ins["property_id"] = pid
            mapping.setdefault(ins.get("nieruchomosc"), pid)
            changed = True

    return changed, mapping, max_num


def property_id_state(inspections: List[Dict]) -> tuple[Dict[str, str], int]:
    mapping: Dict[str, str] = {}
    max_num = 0
    pat = re.compile(r"^P(\\d+)$")
    for ins in inspections:
        pid = ins.get("property_id", "")
        if pid:
            mapping.setdefault(ins.get("nieruchomosc"), pid)
            m = pat.match(pid)
            if m:
                max_num = max(max_num, int(m.group(1)))
    return mapping, max_num


def ensure_properties_table(engine):
    with engine.begin() as conn:
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS properties (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) UNIQUE NOT NULL,
                property_id VARCHAR(32),
                segment VARCHAR(32)
            ) CHARACTER SET utf8mb4;
            """
        )


ensure_properties_table(engine)


def ensure_settings_table(engine):
    with engine.begin() as conn:
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS app_settings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                `key` VARCHAR(100) UNIQUE NOT NULL,
                value TEXT
            ) CHARACTER SET utf8mb4;
            """
        )


ensure_settings_table(engine)


def ensure_users_email_column(engine):
    with engine.begin() as conn:
        res = conn.exec_driver_sql("SHOW COLUMNS FROM users LIKE 'email'").fetchone()
        if not res:
            conn.exec_driver_sql("ALTER TABLE users ADD COLUMN email VARCHAR(255)")


ensure_users_email_column(engine)


def ensure_company_tables(engine):
    with engine.begin() as conn:
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS company_contacts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                company_name VARCHAR(255) NOT NULL,
                contact_name VARCHAR(255),
                phone VARCHAR(64),
                email VARCHAR(255)
            ) CHARACTER SET utf8mb4;
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS company_contact_assignments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                contact_id INT NOT NULL,
                property_name VARCHAR(255) NOT NULL,
                scope VARCHAR(255),
                CONSTRAINT fk_company_contact
                    FOREIGN KEY (contact_id) REFERENCES company_contacts(id)
                    ON DELETE CASCADE
            ) CHARACTER SET utf8mb4;
            """
        )


ensure_company_tables(engine)


def get_or_create_property_id(db, prop_name: str) -> str:
    prop_name = normalize_property_name(prop_name)
    existing = (
        db.query(Inspection.property_id)
        .filter(Inspection.nieruchomosc == prop_name, Inspection.property_id != None)
        .first()
    )
    if existing and existing[0]:
        return existing[0]

    max_num = 0
    pat = re.compile(r"^P(\\d+)$")
    for (pid,) in db.query(Inspection.property_id).filter(
        Inspection.property_id != None
    ):
        m = pat.match(pid or "")
        if m:
            max_num = max(max_num, int(m.group(1)))
    max_num += 1

    ensure_property_record(db, prop_name, property_id=f"P{max_num:04d}")
    return f"P{max_num:04d}"


def get_property_access_map(db) -> Dict[str, List[str]]:
    result = {}
    rows = db.query(PropertyAccess).all()
    for row in rows:
        result.setdefault(row.nieruchomosc, []).append(row.username)
    return result


def get_property_segment_map(db) -> Dict[str, str]:
    return {p.name: (p.segment or "") for p in db.query(Property).all()}


def ensure_property_record(db, name: str, property_id: str = "", segment: str = ""):
    name_norm = normalize_property_name(name)
    prop = db.query(Property).filter_by(name=name_norm).first()
    updated = False
    if not prop:
        prop = Property(
            name=name_norm, property_id=property_id or None, segment=segment or None
        )
        db.add(prop)
        updated = True
    else:
        if property_id and prop.property_id != property_id:
            prop.property_id = property_id
            updated = True
        if segment and prop.segment != segment:
            prop.segment = segment
            updated = True
    if updated:
        db.commit()
    return prop


def get_setting_value(db, key: str, default: str = "") -> str:
    setting = db.query(AppSetting).filter_by(key=key).first()
    return setting.value if setting and setting.value is not None else default


def set_setting_value(db, key: str, value: str):
    setting = db.query(AppSetting).filter_by(key=key).first()
    if not setting:
        setting = AppSetting(key=key, value=value)
        db.add(setting)
    else:
        setting.value = value
    db.commit()


def send_direct_email(to_list: list[str], subject: str, body: str):
    if not to_list or not SMTP_PASSWORD:
        return False
    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(to_list)
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            if SMTP_TLS:
                server.starttls()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception:
        app.logger.exception("SMTP direct send error to %s", to_list)
        return False


def get_recipients_for_inspection(db, ins: Inspection) -> list[str]:
    recipients = []
    owner_user = db.query(User).filter_by(username=ins.owner).first()
    if owner_user and owner_user.email:
        recipients.append(owner_user.email)
    for pa in db.query(PropertyAccess).filter_by(nieruchomosc=ins.nieruchomosc).all():
        u = db.query(User).filter_by(username=pa.username).first()
        if u and u.email:
            recipients.append(u.email)
    return sorted({r.strip() for r in recipients if r.strip()})


def enqueue_email(to_list: list[str], line: str):
    if not to_list or not SMTP_PASSWORD:
        return
    if not hasattr(g, "mail_batch"):
        g.mail_batch = {}
    for recipient in to_list:
        g.mail_batch.setdefault(recipient, []).append(line)


def flush_mail_queue():
    batch = getattr(g, "mail_batch", None)
    if not batch:
        return
    db = get_db()
    subject = get_setting_value(db, "email_upcoming_subject", "Nadchodzące przeglądy")
    header = get_setting_value(
        db,
        "email_upcoming_header",
        "Poniższe przeglądy zmieniły status na Nadchodzące:",
    )
    for recipient, lines in batch.items():
        msg = EmailMessage()
        msg["From"] = SMTP_FROM
        msg["To"] = recipient
        msg["Subject"] = subject
        body = header + "\n\n" + "\n".join(f"- {l}" for l in lines)
        msg.set_content(body)
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                if SMTP_TLS:
                    server.starttls()
                if SMTP_USER:
                    server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
        except Exception:
            app.logger.exception("SMTP send error to %s", recipient)


def send_upcoming_notification(db, ins: Inspection, previous_status: str | None):
    if ins.status != "Nadchodzące":
        return
    if previous_status == "Nadchodzące":
        return
    recipients = get_recipients_for_inspection(db, ins)
    if not recipients:
        return
    line_tmpl = get_setting_value(
        db,
        "email_upcoming_line",
        default="{name} — {property} (termin: {due}) [firma: {company}, email: {company_email}]",
    )
    line = line_tmpl.format(
        name=ins.nazwa,
        property=ins.nieruchomosc,
        due=ins.kolejna_data.strftime("%Y-%m-%d") if ins.kolejna_data else "-",
        company=ins.firma or "",
        company_email=ins.email or "",
    )
    enqueue_email(recipients, line)


def find_user(username: str, db=None) -> Optional[Dict]:
    username = (username or "").strip()
    if not username:
        return None
    db = db or get_db()
    user = db.query(User).filter_by(username=username).first()
    if not user:
        return None
    return {"username": user.username, "role": user.role, "password": user.password}


def is_admin(user: Optional[Dict]) -> bool:
    return bool(user) and user.get("role") == "admin"


def user_can_access(user: Dict, inspection: Dict, prop_access: Dict[str, List[str]]):
    if is_admin(user):
        return True
    username = user.get("username")
    if inspection.get("owner") == username:
        return True
    return username in prop_access.get(inspection.get("nieruchomosc"), [])


@app.before_request
def setup_db():
    g.db = SessionLocal()
    username = session.get("username")
    g.user = find_user(username, db=g.db) if username else None
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(16)
        session["csrf_token"] = token
    g.csrf_token = token
    if request.method == "POST":
        form_token = request.form.get("csrf_token") or request.headers.get(
            "X-CSRF-Token", ""
        )
        if form_token != g.csrf_token:
            return "Błędny token CSRF.", 400


@app.teardown_appcontext
def teardown_db(exc):
    db = getattr(g, "db", None)
    if db:
        db.close()
    try:
        flush_mail_queue()
    except Exception:
        pass


@app.context_processor
def inject_user():
    return {
        "current_user": g.get("user"),
        "csrf_token": g.get("csrf_token"),
        "app_version": APP_VERSION,
    }


def log_event(action: str, user: str, details: Dict, db_session=None):
    db = db_session or get_db()
    try:
        evt = Audit(ts=datetime.utcnow(), action=action, user=user, details=details)
        db.add(evt)
        db.commit()
    except Exception:
        db.rollback()


def get_db():
    if not hasattr(g, "db"):
        g.db = SessionLocal()
    return g.db


def ensure_occurrences_for_inspection(db, ins: Inspection, commit: bool = True) -> bool:
    if ins.occurrences:
        return False
    if ins.ostatnia_data:
        db.add(
            InspectionOccurrence(
                inspection_id=ins.id,
                due_date=ins.ostatnia_data,
                done_date=ins.ostatnia_data,
                status="done",
                performed_by=ins.owner,
                note="Import historyczny",
            )
        )
    if ins.kolejna_data:
        db.add(
            InspectionOccurrence(
                inspection_id=ins.id,
                due_date=ins.kolejna_data,
                status="planned",
                note="Plan automatyczny",
            )
        )
    if commit:
        db.commit()
    return True


def ensure_occurrences_seed(db):
    added = False
    for ins in db.query(Inspection).all():
        added = ensure_occurrences_for_inspection(db, ins, commit=False) or added
    if added:
        db.commit()


def ensure_properties_seed(db):
    for ins in db.query(Inspection).all():
        ensure_property_record(
            db,
            ins.nieruchomosc,
            property_id=ins.property_id or "",
            segment=ins.segment or "",
        )


def compute_next_and_status(last_date_str: str, freq: int) -> tuple[str, str]:
    last = parse_date(last_date_str)
    next_dt = add_months(last, freq)
    today = date.today()

    if next_dt < today:
        status = "Zaległy"
    elif (next_dt - today).days <= 30:
        status = "Nadchodzące"
    else:
        status = "Aktualne"

    return next_dt.isoformat(), status


def get_unique(inspections: List[Dict], key: str) -> List[str]:
    return sorted({i.get(key, "") for i in inspections if i.get(key)})


def compute_property_owner_map(inspections: List[Dict]) -> Dict[str, str]:
    owners: Dict[str, str] = {}
    for ins in inspections:
        prop = ins.get("nieruchomosc")
        if prop and prop not in owners:
            owners[prop] = ins.get("owner", "")
    return owners


def slugify_property(prop: str) -> str:
    return (
        (prop or "")
        .replace(" ", "_")
        .replace("/", "_")
        .replace(".", "_")
        .replace(",", "_")
        .replace(":", "_")
    )


def user_can_manage_access(user: Dict, inspection: Dict) -> bool:
    if is_admin(user):
        return True
    return inspection.get("owner") == user.get("username")


def add_new_planned_occurrence(db, ins: Inspection, done_date: date):
    before_status = ins.status
    next_due = add_months(done_date, ins.czestotliwosc_miesiace)
    ins.ostatnia_data = done_date
    ins.kolejna_data = next_due
    today = date.today()
    if next_due < today:
        ins.status = "Zaległy"
    elif (next_due - today).days <= 30:
        ins.status = "Nadchodzące"
    else:
        ins.status = "Aktualne"
    db.add(
        InspectionOccurrence(
            inspection_id=ins.id,
            due_date=next_due,
            status="planned",
            note="Plan po wykonaniu",
        )
    )
    db.commit()
    send_upcoming_notification(db, ins, previous_status=before_status)


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not g.get("user"):
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)

    return wrapper


def load_inspections_for_user(db, user):
    ensure_occurrences_seed(db)
    ensure_properties_seed(db)
    prop_access = get_property_access_map(db)
    prop_segments = get_property_segment_map(db)

    inspections = []
    for ins in db.query(Inspection).all():
        seg_val = prop_segments.get(ins.nieruchomosc) or ins.segment or ""
        ins_dict = {
            "id": ins.id,
            "nazwa": ins.nazwa,
            "nieruchomosc": ins.nieruchomosc,
            "property_id": ins.property_id or "",
            "ostatnia_data": ins.ostatnia_data.isoformat() if ins.ostatnia_data else "",
            "czestotliwosc_miesiace": ins.czestotliwosc_miesiace,
            "kolejna_data": ins.kolejna_data.isoformat() if ins.kolejna_data else "",
            "status": ins.status,
            "opis": ins.opis or "",
            "firma": ins.firma or "",
            "telefon": ins.telefon or "",
            "email": ins.email or "",
            "segment": seg_val,
            "owner": ins.owner,
        }
        if user_can_access(user, ins_dict, prop_access):
            ins_dict["idx"] = ins.id
            inspections.append(ins_dict)
    return inspections


def filter_inspections(inspections, args):
    f_n = [v.strip() for v in args.getlist("nieruchomosc") if v.strip()]
    f_name = [v.strip() for v in args.getlist("nazwa") if v.strip()]
    f_status = [v.strip() for v in args.getlist("status") if v.strip()]
    f_uwagi = [v.strip() for v in args.getlist("uwagi") if v.strip()]
    f_segment = [v.strip() for v in args.getlist("segment") if v.strip()]
    f_q = args.get("q", "").strip().lower()
    sort_by = args.get("sort", "default")

    filtered = []
    for ins in inspections:
        opis = (ins.get("opis") or "").strip()
        ok = True

        if f_n and ins.get("nieruchomosc") not in f_n:
            ok = False
        if f_name and ins.get("nazwa") not in f_name:
            ok = False
        if f_status and ins.get("status") not in f_status:
            ok = False
        has_tak = "tak" in f_uwagi
        has_nie = "nie" in f_uwagi
        if has_tak and not has_nie and opis.lower() in ("", "brak uwag"):
            ok = False
        if has_nie and not has_tak and opis.lower() not in ("", "brak uwag"):
            ok = False
        if f_segment and ins.get("segment") not in f_segment:
            ok = False
        if f_q:
            hay = " ".join(
                [
                    ins.get("nazwa", ""),
                    ins.get("nieruchomosc", ""),
                ]
            ).lower()
            if f_q not in hay:
                ok = False

        if ok:
            row = ins.copy()
            row["idx"] = ins.get("id") or ins.get("idx")
            filtered.append(row)

    status_order = {
        "Zaległy": 0,
        "Nadchodzące": 1,
        "Aktualne": 2,
    }

    def safe_date(d):
        try:
            return date.fromisoformat(d)
        except Exception:
            return date(9999, 12, 31)

    if sort_by == "nazwa":
        filtered.sort(
            key=lambda ins: (ins.get("nazwa", ""), ins.get("nieruchomosc", ""))
        )
    elif sort_by == "kolejna_data":
        filtered.sort(
            key=lambda ins: (safe_date(ins.get("kolejna_data")), ins.get("nazwa", ""))
        )
    elif sort_by == "nieruchomosc":
        filtered.sort(
            key=lambda ins: (
                ins.get("nieruchomosc", ""),
                ins.get("property_id", ""),
                ins.get("nazwa", ""),
            )
        )
    else:
        filtered.sort(
            key=lambda ins: (
                ins.get("nieruchomosc", ""),
                status_order.get(ins.get("status"), 99),
                safe_date(ins.get("kolejna_data")),
                ins.get("nazwa", ""),
            )
        )
    return filtered


def build_property_cards(inspections, args):
    current_properties = [v.strip() for v in args.getlist("nieruchomosc") if v.strip()]
    current_property = current_properties[0] if len(current_properties) == 1 else ""
    base_args = args.to_dict(flat=False)
    base_args.pop("page", None)

    cards_map: Dict[str, Dict] = {}
    for ins in inspections:
        prop = ins.get("nieruchomosc")
        if not prop:
            continue

        entry = cards_map.setdefault(
            prop,
            {
                "name": prop,
                "segment": ins.get("segment") or "",
                "property_id": ins.get("property_id") or "",
                "overdue": 0,
                "upcoming": 0,
                "current": 0,
                "total": 0,
                "next_due": None,
            },
        )
        status = ins.get("status")
        if status == "Zaległy":
            entry["overdue"] += 1
        elif status == "Nadchodzące":
            entry["upcoming"] += 1
        elif status:
            entry["current"] += 1
        entry["total"] += 1

        due_raw = ins.get("kolejna_data")
        if due_raw:
            try:
                due_date = date.fromisoformat(due_raw)
                if entry["next_due"] is None or due_date < entry["next_due"]:
                    entry["next_due"] = due_date
            except ValueError:
                pass

    cards: List[Dict] = []
    for prop in sorted(cards_map.keys()):
        data = cards_map[prop]
        params = base_args.copy()
        params["nieruchomosc"] = prop
        next_label = data["next_due"].strftime("%d.%m.%Y") if data["next_due"] else ""
        cards.append(
            {
                **data,
                "link": url_for("index", **params),
                "active": current_property == prop,
                "next_due_label": next_label,
            }
        )
    return cards


@app.route("/")
@login_required
def index():
    db = get_db()
    inspections = load_inspections_for_user(db, g.user)
    filtered = filter_inspections(inspections, request.args)

    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    per_page = 15

    used_properties = get_unique(inspections, "nieruchomosc")
    used_names = get_unique(inspections, "nazwa")
    used_status = get_unique(inspections, "status")
    used_segments = get_unique(inspections, "segment")
    property_cards = build_property_cards(inspections, request.args)
    selected_properties = [v for v in request.args.getlist("nieruchomosc") if v]
    selected_names = [v for v in request.args.getlist("nazwa") if v]
    selected_status = [v for v in request.args.getlist("status") if v]
    selected_uwagi = [v for v in request.args.getlist("uwagi") if v]
    selected_segments = [v for v in request.args.getlist("segment") if v]
    active_filter_count = (
        len(selected_properties)
        + len(selected_names)
        + len(selected_status)
        + len(selected_uwagi)
        + len(selected_segments)
    )

    total = len(filtered)
    total_pages = max(1, ceil(total / per_page)) if total else 1
    if page > total_pages:
        page = total_pages
    start = (page - 1) * per_page
    end = start + per_page
    page_items = filtered[start:end]

    args_dict = request.args.to_dict(flat=False)
    args_no_page = args_dict.copy()
    args_no_page.pop("page", None)
    clear_property_url = url_for(
        "index", **{k: v for k, v in args_no_page.items() if k != "nieruchomosc"}
    )
    clear_filters_url = url_for(
        "index",
        **{
            k: v
            for k, v in args_no_page.items()
            if k not in {"nieruchomosc", "nazwa", "status", "uwagi", "segment", "sort"}
        },
    )

    def build_page_url(num):
        params = args_dict.copy()
        params["page"] = num
        return url_for("index", **params)

    prev_url = build_page_url(page - 1) if page > 1 else None
    next_url = build_page_url(page + 1) if page < total_pages else None

    return render_template(
        "index.html",
        inspections=page_items,
        used_properties=used_properties,
        used_names=used_names,
        used_status=used_status,
        used_uwagi=["tak", "nie"],
        used_segments=used_segments,
        property_cards=property_cards,
        selected_properties=selected_properties,
        selected_names=selected_names,
        selected_status=selected_status,
        selected_uwagi=selected_uwagi,
        selected_segments=selected_segments,
        active_filter_count=active_filter_count,
        clear_property_url=clear_property_url,
        clear_filters_url=clear_filters_url,
        page=page,
        total_pages=total_pages,
        prev_url=prev_url,
        next_url=next_url,
        total_items=total,
        per_page=per_page,
        args_dict=args_dict,
    )


@app.route("/firms")
@login_required
def firm_index():
    db = get_db()
    ensure_company_seed(db)
    inspections = load_inspections_for_user(db, g.user)
    allowed_properties = {i.get("nieruchomosc") for i in inspections if i.get("nieruchomosc")}
    companies, _ = build_company_directory(db, allowed_properties=allowed_properties)

    q = request.args.get("q", "").strip()
    selected_property = request.args.get("property", "").strip()
    selected_scope = request.args.get("scope", "").strip()
    q_lower = q.lower()

    def matches(company):
        if selected_property and selected_property not in company["properties"]:
            return False
        if selected_scope and selected_scope not in company["scopes"]:
            return False
        if q_lower:
            hay = " ".join(
                [company["name"]]
                + company["emails"]
                + company["phones"]
                + company["properties"]
                + company["scopes"]
            ).lower()
            if q_lower not in hay:
                return False
        return True

    filtered = [c for c in companies if matches(c)]
    used_properties = get_unique(inspections, "nieruchomosc")
    used_scopes = get_unique(inspections, "nazwa")

    return render_template(
        "firms.html",
        firms=filtered,
        q=q,
        used_properties=used_properties,
        used_scopes=used_scopes,
        selected_property=selected_property,
        selected_scope=selected_scope,
    )


@app.route("/firms/<path:company>")
@login_required
def firm_detail(company: str):
    db = get_db()
    ensure_company_seed(db)
    inspections = load_inspections_for_user(db, g.user)
    allowed_properties = {i.get("nieruchomosc") for i in inspections if i.get("nieruchomosc")}
    key = normalize_company_key(company)
    all_contacts = db.query(CompanyContact).all()
    contacts = [c for c in all_contacts if normalize_company_key(c.company_name) == key]
    if not contacts:
        return "Nie znaleziono firmy.", 404

    contact_ids = [c.id for c in contacts]
    assignments = (
        db.query(CompanyContactAssignment)
        .filter(CompanyContactAssignment.contact_id.in_(contact_ids))
        .all()
    )
    assignments_map = {}
    for assignment in assignments:
        assignments_map.setdefault(assignment.contact_id, []).append(assignment)

    contacts_data = []
    properties = set()
    scopes = set()
    for contact in contacts:
        prop_map = {}
        for assignment in assignments_map.get(contact.id, []):
            if allowed_properties is not None and assignment.property_name not in allowed_properties:
                continue
            prop_map.setdefault(assignment.property_name, []).append(
                {"id": assignment.id, "scope": assignment.scope or ""}
            )
            properties.add(assignment.property_name)
            if assignment.scope:
                scopes.add(assignment.scope)
        if allowed_properties is not None and not prop_map:
            continue
        prop_list = []
        for prop, items in prop_map.items():
            scope_list = sorted({i["scope"] for i in items if i["scope"]})
            prop_list.append({"name": prop, "items": items, "scopes": scope_list})
        prop_list.sort(key=lambda p: p["name"].lower())
        contacts_data.append(
            {
                "id": contact.id,
                "name": contact.contact_name or "",
                "phone": contact.phone or "",
                "email": contact.email or "",
                "properties": prop_list,
            }
        )

    if not contacts_data:
        return "Nie znaleziono firmy.", 404

    firm_data = {
        "key": key,
        "name": contacts[0].company_name,
        "contacts": contacts_data,
        "contact_count": len(contacts_data),
        "property_count": len(properties),
        "scope_count": len(scopes),
    }

    used_properties = get_unique(inspections, "nieruchomosc")
    used_scopes = get_unique(inspections, "nazwa")
    edit_contact_id = request.args.get("edit")
    try:
        edit_contact_id = int(edit_contact_id) if edit_contact_id else None
    except ValueError:
        edit_contact_id = None

    return render_template(
        "firm_detail.html",
        firm=firm_data,
        used_properties=used_properties,
        used_scopes=used_scopes,
        edit_contact_id=edit_contact_id,
    )


@app.route("/firms/<path:company>/contacts/add", methods=["POST"])
@login_required
def firm_contact_add(company: str):
    db = get_db()
    company_name = " ".join((request.form.get("company_name") or company).split())
    if not company_name:
        return "Brak firmy.", 400
    contact = CompanyContact(
        company_name=company_name,
        contact_name=(request.form.get("contact_name") or "").strip(),
        phone=(request.form.get("phone") or "").strip(),
        email=(request.form.get("email") or "").strip(),
    )
    db.add(contact)
    db.commit()
    return redirect(url_for("firm_detail", company=company_name))


@app.route("/firms/<path:company>/contacts/<int:contact_id>/update", methods=["POST"])
@login_required
def firm_contact_update(company: str, contact_id: int):
    db = get_db()
    contact = db.query(CompanyContact).filter_by(id=contact_id).first()
    if not contact:
        return "Nie znaleziono kontaktu.", 404
    if normalize_company_key(contact.company_name) != normalize_company_key(company):
        return "Brak dostępu.", 403
    contact.contact_name = (request.form.get("contact_name") or "").strip()
    contact.phone = (request.form.get("phone") or "").strip()
    contact.email = (request.form.get("email") or "").strip()
    db.commit()
    return redirect(url_for("firm_detail", company=contact.company_name))


@app.route("/firms/<path:company>/contacts/<int:contact_id>/delete", methods=["POST"])
@login_required
def firm_contact_delete(company: str, contact_id: int):
    db = get_db()
    contact = db.query(CompanyContact).filter_by(id=contact_id).first()
    if not contact:
        return "Nie znaleziono kontaktu.", 404
    if normalize_company_key(contact.company_name) != normalize_company_key(company):
        return "Brak dostępu.", 403
    company_name = contact.company_name
    db.delete(contact)
    db.commit()
    return redirect(url_for("firm_detail", company=company_name))


@app.route("/firms/<path:company>/contacts/<int:contact_id>/assignments/add", methods=["POST"])
@login_required
def firm_assignment_add(company: str, contact_id: int):
    db = get_db()
    contact = db.query(CompanyContact).filter_by(id=contact_id).first()
    if not contact:
        return "Nie znaleziono kontaktu.", 404
    if normalize_company_key(contact.company_name) != normalize_company_key(company):
        return "Brak dostępu.", 403
    property_name = (request.form.get("property_name") or "").strip()
    scope = (request.form.get("scope_custom") or request.form.get("scope") or "").strip()
    if not property_name:
        return "Brak nieruchomości.", 400
    existing = (
        db.query(CompanyContactAssignment)
        .filter_by(contact_id=contact.id, property_name=property_name, scope=scope)
        .first()
    )
    if not existing:
        db.add(
            CompanyContactAssignment(
                contact_id=contact.id,
                property_name=property_name,
                scope=scope,
            )
        )
        db.commit()
    return redirect(url_for("firm_detail", company=contact.company_name))


@app.route(
    "/firms/<path:company>/contacts/<int:contact_id>/assignments/<int:assignment_id>/delete",
    methods=["POST"],
)
@login_required
def firm_assignment_delete(company: str, contact_id: int, assignment_id: int):
    db = get_db()
    contact = db.query(CompanyContact).filter_by(id=contact_id).first()
    if not contact:
        return "Nie znaleziono kontaktu.", 404
    if normalize_company_key(contact.company_name) != normalize_company_key(company):
        return "Brak dostępu.", 403
    assignment = (
        db.query(CompanyContactAssignment)
        .filter_by(id=assignment_id, contact_id=contact_id)
        .first()
    )
    if assignment:
        db.delete(assignment)
        db.commit()
    return redirect(url_for("firm_detail", company=contact.company_name))


@app.route("/export")
@app.route("/export.csv")
@login_required
def export_csv():
    db = get_db()
    inspections = load_inspections_for_user(db, g.user)
    filtered = filter_inspections(inspections, request.args)

    output = io.StringIO()
    writer = csv.writer(output, delimiter=";", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(
        [
            "ID",
            "Nieruchomość",
            "Nazwa",
            "Segment",
            "Firma",
            "Telefon",
            "Email",
            "Ostatnia data",
            "Kolejna data",
            "Status",
            "Uwagi",
        ]
    )
    for ins in filtered:
        writer.writerow(
            [
                ins.get("id") or ins.get("idx"),
                format_property(ins.get("nieruchomosc", "")),
                ins.get("nazwa", ""),
                ins.get("segment", ""),
                ins.get("firma", ""),
                ins.get("telefon", ""),
                ins.get("email", ""),
                ins.get("ostatnia_data", ""),
                ins.get("kolejna_data", ""),
                ins.get("status", ""),
                (ins.get("opis") or "").replace("\n", " ").strip(),
            ]
        )

    csv_data = output.getvalue().encode("utf-8-sig")
    return Response(
        csv_data,
        mimetype="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f"attachment; filename={export_filename('csv')}"
        },
    )


@app.route("/export.xlsx")
@login_required
def export_xlsx():
    db = get_db()
    inspections = load_inspections_for_user(db, g.user)
    filtered = filter_inspections(inspections, request.args)

    wb = Workbook()
    ws = wb.active
    ws.title = "Przeglady"

    headers = [
        "ID",
        "Nieruchomość",
        "Nazwa",
        "Segment",
        "Firma",
        "Telefon",
        "Email",
        "Ostatnia data",
        "Kolejna data",
        "Status",
        "Uwagi",
    ]
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True)

    def parse_iso(raw: str):
        try:
            return date.fromisoformat(raw)
        except Exception:
            return None

    for ins in filtered:
        last_date = parse_iso(ins.get("ostatnia_data", ""))
        next_date = parse_iso(ins.get("kolejna_data", ""))
        ws.append(
            [
                ins.get("id") or ins.get("idx"),
                format_property(ins.get("nieruchomosc", "")),
                ins.get("nazwa", ""),
                ins.get("segment", ""),
                ins.get("firma", ""),
                ins.get("telefon", ""),
                ins.get("email", ""),
                last_date,
                next_date,
                ins.get("status", ""),
                (ins.get("opis") or "").replace("\n", " ").strip(),
            ]
        )

    date_cols = [8, 9]
    for row in ws.iter_rows(min_row=2, min_col=1, max_col=len(headers)):
        for idx in date_cols:
            cell = row[idx - 1]
            if isinstance(cell.value, date):
                cell.number_format = "yyyy-mm-dd"

    widths = [len(h) for h in headers]
    for row in ws.iter_rows(min_row=2, max_col=len(headers)):
        for i, cell in enumerate(row):
            value = cell.value
            if isinstance(value, date):
                text = value.isoformat()
            elif value is None:
                text = ""
            else:
                text = str(value)
            widths[i] = max(widths[i], len(text))
    for i, width in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(i)].width = min(max(width + 2, 10), 40)

    ws.freeze_panes = "A2"

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f"attachment; filename={export_filename('xlsx')}"
        },
    )


def extract_form():
    shared_raw = request.form.getlist("shared_with")
    property_shared_raw = request.form.getlist("property_shared_with")
    return {
        "nazwa": request.form.get("nazwa", "").strip(),
        "nieruchomosc": request.form.get("nieruchomosc", "").strip(),
        "ostatnia_data": request.form.get("ostatnia_data", "").strip(),
        "czestotliwosc_miesiace": request.form.get(
            "czestotliwosc_miesiace", ""
        ).strip(),
        "opis": request.form.get("opis", "").strip(),
        "firma": request.form.get("firma", "").strip(),
        "telefon": request.form.get("telefon", "").strip(),
        "email": request.form.get("email", "").strip(),
        "segment": request.form.get("segment", "").strip(),
        "owner": request.form.get("owner", "").strip(),
        "shared_with": [u.strip() for u in shared_raw if u.strip()],
        "property_shared_with": [u.strip() for u in property_shared_raw if u.strip()],
    }


def validate_form(form):
    errors = {}

    if not form["nazwa"]:
        errors["nazwa"] = "Nazwa jest wymagana."

    if not form["nieruchomosc"]:
        errors["nieruchomosc"] = "Nieruchomość jest wymagana."

    if not form["segment"]:
        errors["segment"] = "Wybierz segment — Detal, Hurt lub Pozostałe."

    email = form.get("email", "")
    if email:
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            errors["email"] = "Podaj poprawny adres e-mail."

    phone = form.get("telefon", "")
    if phone:
        try:
            form["telefon"] = normalize_phone(phone)
        except ValueError as e:
            errors["telefon"] = str(e)

    try:
        parse_date(form["ostatnia_data"])
    except ValueError as e:
        errors["ostatnia_data"] = str(e)

    try:
        freq = int(form["czestotliwosc_miesiace"])
        if freq <= 0:
            raise ValueError
    except ValueError:
        errors["czestotliwosc_miesiace"] = (
            "Częstotliwość musi być dodatnią liczbą całkowitą."
        )

    return errors


def build_company_contacts(inspections):
    result = {}
    for ins in inspections:
        firma = ins.get("firma")
        if firma:
            result[firma] = {
                "telefon": ins.get("telefon", ""),
                "email": ins.get("email", ""),
            }
    return result


def normalize_company_key(name: str) -> str:
    return " ".join((name or "").strip().split()).lower()


def ensure_company_seed(db):
    contacts = db.query(CompanyContact).all()
    contact_map = {}
    existing_companies = set()
    for contact in contacts:
        key = (
            normalize_company_key(contact.company_name),
            (contact.phone or "").strip().lower(),
            (contact.email or "").strip().lower(),
        )
        contact_map[key] = contact
        existing_companies.add(normalize_company_key(contact.company_name))

    assignment_keys = {
        (a.contact_id, a.property_name, a.scope or "")
        for a in db.query(CompanyContactAssignment).all()
    }

    changed = False
    for ins in db.query(Inspection).all():
        company = " ".join((ins.firma or "").strip().split())
        if not company:
            continue
        company_key = normalize_company_key(company)
        if company_key in existing_companies:
            continue
        phone = " ".join((ins.telefon or "").strip().split())
        email = (ins.email or "").strip()
        key = (company_key, phone.lower(), email.lower())
        contact = contact_map.get(key)
        if not contact:
            contact = CompanyContact(
                company_name=company,
                contact_name="",
                phone=phone,
                email=email,
            )
            db.add(contact)
            db.flush()
            contact_map[key] = contact
            changed = True

        prop = " ".join((ins.nieruchomosc or "").strip().split())
        scope = " ".join((ins.nazwa or "").strip().split())
        if prop:
            akey = (contact.id, prop, scope)
            if akey not in assignment_keys:
                db.add(
                    CompanyContactAssignment(
                        contact_id=contact.id,
                        property_name=prop,
                        scope=scope,
                    )
                )
                assignment_keys.add(akey)
                changed = True

    if changed:
        db.commit()


def build_company_directory(db, allowed_properties=None):
    contacts = db.query(CompanyContact).all()
    assignments = db.query(CompanyContactAssignment).all()
    contact_props = {}
    for assignment in assignments:
        if allowed_properties is not None and assignment.property_name not in allowed_properties:
            continue
        contact_props.setdefault(assignment.contact_id, []).append(assignment)

    companies = {}
    for contact in contacts:
        company = " ".join((contact.company_name or "").strip().split())
        if not company:
            continue
        key = normalize_company_key(company)
        entry = companies.setdefault(key, {"name": company, "contacts": []})
        assignments_list = contact_props.get(contact.id, [])
        properties = {}
        for assignment in assignments_list:
            prop = assignment.property_name
            scope = assignment.scope or ""
            scopes = properties.setdefault(prop, set())
            if scope:
                scopes.add(scope)
        if allowed_properties is not None and not properties:
            continue
        prop_list = [
            {"name": prop, "scopes": sorted(scope_set)}
            for prop, scope_set in properties.items()
        ]
        prop_list.sort(key=lambda p: p["name"].lower())
        entry["contacts"].append(
            {
                "id": contact.id,
                "name": contact.contact_name or "",
                "phone": contact.phone or "",
                "email": contact.email or "",
                "properties": prop_list,
            }
        )

    directory = {}
    for key, entry in companies.items():
        contacts_list = entry["contacts"]
        contacts_list.sort(key=lambda c: (c["email"] or "", c["phone"] or ""))
        properties = set()
        scopes = set()
        emails = set()
        phones = set()
        for contact in contacts_list:
            if contact["email"]:
                emails.add(contact["email"])
            if contact["phone"]:
                phones.add(contact["phone"])
            for prop in contact["properties"]:
                properties.add(prop["name"])
                scopes.update(prop["scopes"])
        scope_list = sorted(scopes)
        scope_summary = ", ".join(scope_list[:3])
        if len(scope_list) > 3:
            scope_summary = f"{scope_summary}..."
        email_list = sorted(emails)
        phone_list = sorted(phones)
        directory[key] = {
            "key": key,
            "name": entry["name"],
            "contacts": contacts_list,
            "contact_count": len(contacts_list),
            "property_count": len(properties),
            "scope_count": len(scope_list),
            "properties": sorted(properties),
            "scopes": scope_list,
            "scope_summary": scope_summary,
            "emails": email_list,
            "phones": phone_list,
            "primary_email": email_list[0] if email_list else "",
            "primary_phone": phone_list[0] if phone_list else "",
        }
    companies_list = sorted(directory.values(), key=lambda c: c["name"].lower())
    return companies_list, directory


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    db = get_db()
    prop_access_map = get_property_access_map(db)
    prop_segments = get_property_segment_map(db)
    inspections = []
    for ins in db.query(Inspection).all():
        seg_val = prop_segments.get(ins.nieruchomosc) or ins.segment or ""
        ins_dict = {
            "nazwa": ins.nazwa,
            "nieruchomosc": ins.nieruchomosc,
            "ostatnia_data": ins.ostatnia_data.isoformat() if ins.ostatnia_data else "",
            "czestotliwosc_miesiace": ins.czestotliwosc_miesiace,
            "opis": ins.opis or "",
            "firma": ins.firma or "",
            "telefon": ins.telefon or "",
            "email": ins.email or "",
            "segment": seg_val,
            "owner": ins.owner,
        }
        if user_can_access(g.user, ins_dict, prop_access_map):
            inspections.append(ins_dict)

        if request.method == "POST":
            form = extract_form()
        else:
            form = {
                "nazwa": "",
                "nieruchomosc": "",
                "ostatnia_data": "",
                "czestotliwosc_miesiace": "",
                "opis": "",
                "firma": "",
                "telefon": "",
                "email": "",
                "segment": "",
                "shared_with": [],
                "owner": g.user["username"],
                "property_shared_with": [],
            }

    errors = validate_form(form) if request.method == "POST" else {}

    if request.method == "POST" and not errors:
        freq = int(form["czestotliwosc_miesiace"])
        next_dt, status = compute_next_and_status(form["ostatnia_data"], freq)
        seg_val = form["segment"]

        prop_name = normalize_property_name(form["nieruchomosc"])
        pid = get_or_create_property_id(db, prop_name)
        seg_val = form["segment"]
        ensure_property_record(db, prop_name, property_id=pid, segment=seg_val)

        owner_val = form.get("owner") or g.user["username"]
        if not is_admin(g.user):
            owner_val = g.user["username"]
            form["property_shared_with"] = []

        new_ins = Inspection(
            nazwa=form["nazwa"],
            nieruchomosc=prop_name,
            property_id=pid,
            ostatnia_data=parse_date(form["ostatnia_data"]),
            czestotliwosc_miesiace=freq,
            kolejna_data=date.fromisoformat(next_dt),
            status=status,
            opis=clean_empty_notes(form["opis"]),
            firma=form["firma"],
            telefon=form["telefon"],
            email=form["email"],
            segment=seg_val,
            owner=owner_val,
        )
        db.add(new_ins)
        db.commit()
        ensure_occurrences_for_inspection(db, new_ins)
        send_upcoming_notification(db, new_ins, previous_status=None)

        if is_admin(g.user):
            db.query(PropertyAccess).filter(
                PropertyAccess.nieruchomosc == prop_name
            ).delete()
            for u in form.get("property_shared_with", []):
                db.add(PropertyAccess(nieruchomosc=prop_name, username=u))
            db.commit()

        log_event(
            "add_inspection",
            g.user["username"],
            {
                "property": prop_name,
                "property_id": pid,
                "name": form["nazwa"],
                "owner": owner_val,
            },
            db_session=db,
        )
        return redirect(url_for("index"))

    return render_template(
        "form.html",
        mode="add",
        errors=errors,
        form=form,
        used_names=get_unique(inspections, "nazwa"),
        used_properties=get_unique(inspections, "nieruchomosc"),
        used_companies=get_unique(inspections, "firma"),
        company_contacts=build_company_contacts(inspections),
        all_users=db.query(User).all(),
        property_access=prop_access_map,
    )


@app.route("/edit/<int:idx>", methods=["GET", "POST"])
@login_required
def edit(idx: int):
    db = get_db()
    prop_access = get_property_access_map(db)
    ins_obj = db.query(Inspection).filter_by(id=idx).first()
    if not ins_obj:
        return "Nie znaleziono przeglądu.", 404

    ins_dict = {
        "nazwa": ins_obj.nazwa,
        "nieruchomosc": ins_obj.nieruchomosc,
        "opis": ins_obj.opis or "",
        "firma": ins_obj.firma or "",
        "telefon": ins_obj.telefon or "",
        "email": ins_obj.email or "",
        "segment": ins_obj.segment or "",
        "owner": ins_obj.owner,
    }
    if not user_can_access(g.user, ins_dict, prop_access):
        return "Brak dostępu do tego przeglądu.", 403

    accessible = []
    for i in db.query(Inspection).all():
        d = {
            "nazwa": i.nazwa,
            "nieruchomosc": i.nieruchomosc,
            "firma": i.firma or "",
            "owner": i.owner,
            "segment": i.segment or "",
        }
        if user_can_access(g.user, d, prop_access):
            accessible.append(d)

    if request.method == "POST":
        form = extract_form()
        errors = validate_form(form)

        if not errors:
            freq = int(form["czestotliwosc_miesiace"])
            next_dt, status = compute_next_and_status(form["ostatnia_data"], freq)
            before_owner = ins_obj.owner
            before_status = ins_obj.status

            new_owner = form.get("owner") or ins_obj.owner
            seg_val = form["segment"]
            if not is_admin(g.user):
                new_owner = ins_obj.owner
                form["property_shared_with"] = prop_access.get(ins_obj.nieruchomosc, [])

            new_prop_name = normalize_property_name(form["nieruchomosc"])
            pid = ins_obj.property_id or get_or_create_property_id(db, new_prop_name)
            ensure_property_record(db, new_prop_name, property_id=pid, segment=seg_val)

            ins_obj.nazwa = form["nazwa"]
            ins_obj.nieruchomosc = new_prop_name
            ins_obj.property_id = pid
            ins_obj.ostatnia_data = parse_date(form["ostatnia_data"])
            ins_obj.czestotliwosc_miesiace = freq
            ins_obj.kolejna_data = date.fromisoformat(next_dt)
            ins_obj.status = status
            ins_obj.opis = clean_empty_notes(form["opis"])
            ins_obj.firma = form["firma"]
            ins_obj.telefon = form["telefon"]
            ins_obj.email = form["email"]
            ins_obj.segment = seg_val
            ins_obj.owner = new_owner

            db.commit()
            ensure_occurrences_for_inspection(db, ins_obj)
            upcoming = (
                db.query(InspectionOccurrence)
                .filter_by(inspection_id=ins_obj.id, status="planned")
                .order_by(InspectionOccurrence.due_date.asc())
                .first()
            )
            if upcoming:
                upcoming.due_date = ins_obj.kolejna_data
                db.commit()

            if is_admin(g.user):
                db.query(PropertyAccess).filter(
                    PropertyAccess.nieruchomosc == new_prop_name
                ).delete()
                for u in form.get("property_shared_with", []):
                    db.add(PropertyAccess(nieruchomosc=new_prop_name, username=u))
                db.commit()

            log_event(
                "edit_inspection",
                g.user["username"],
                {
                    "property": ins_obj.nieruchomosc,
                    "property_id": ins_obj.property_id or "",
                    "name": ins_obj.nazwa,
                    "owner_before": before_owner,
                    "owner_after": ins_obj.owner,
                },
                db_session=db,
            )
            send_upcoming_notification(db, ins_obj, previous_status=before_status)
            return redirect(url_for("index"))

    else:
        form = {
            "nazwa": ins_obj.nazwa,
            "nieruchomosc": ins_obj.nieruchomosc,
            "ostatnia_data": (
                ins_obj.ostatnia_data.isoformat() if ins_obj.ostatnia_data else ""
            ),
            "czestotliwosc_miesiace": str(ins_obj.czestotliwosc_miesiace),
            "opis": ins_obj.opis or "",
            "firma": ins_obj.firma or "",
            "telefon": ins_obj.telefon or "",
            "email": ins_obj.email or "",
            "segment": ins_obj.segment or "",
            "owner": ins_obj.owner,
            "shared_with": [],
            "property_shared_with": prop_access.get(ins_obj.nieruchomosc, []),
        }
        errors = {}

    return render_template(
        "form.html",
        mode="edit",
        errors=errors,
        form=form,
        used_names=get_unique(accessible, "nazwa"),
        used_properties=get_unique(accessible, "nieruchomosc"),
        used_companies=get_unique(accessible, "firma"),
        company_contacts=build_company_contacts(accessible),
        all_users=db.query(User).all(),
        property_access=prop_access,
    )


@app.route("/delete/<int:idx>", methods=["POST"])
@login_required
def delete(idx: int):
    db = get_db()
    prop_access = get_property_access_map(db)
    ins = db.query(Inspection).filter_by(id=idx).first()
    if not ins:
        return "Nie znaleziono przeglądu.", 404
    ins_dict = {
        "nazwa": ins.nazwa,
        "nieruchomosc": ins.nieruchomosc,
        "owner": ins.owner,
    }
    if not user_can_access(g.user, ins_dict, prop_access):
        return "Brak dostępu do tego przeglądu.", 403

    db.query(InspectionOccurrence).filter_by(inspection_id=ins.id).delete()
    db.delete(ins)
    db.commit()
    log_event(
        "delete_inspection",
        g.user["username"],
        {
            "property": ins.nieruchomosc,
            "property_id": ins.property_id or "",
            "name": ins.nazwa,
            "owner": ins.owner,
        },
        db_session=db,
    )
    return redirect(url_for("index"))


@app.route("/occurrence/<int:occ_id>/complete", methods=["POST"])
@login_required
def complete_occurrence(occ_id: int):
    db = get_db()
    occ = db.query(InspectionOccurrence).filter_by(id=occ_id).first()
    if not occ:
        return "Brak wystąpienia.", 404

    ins = db.query(Inspection).filter_by(id=occ.inspection_id).first()
    if not ins:
        return "Brak przeglądu.", 404

    prop_access = get_property_access_map(db)
    ins_dict = {
        "nazwa": ins.nazwa,
        "nieruchomosc": ins.nieruchomosc,
        "owner": ins.owner,
    }
    if not user_can_access(g.user, ins_dict, prop_access):
        return "Brak dostępu.", 403

    done_str = request.form.get("done_date", "").strip()
    done_dt = date.today()
    if done_str:
        try:
            done_dt = parse_date(done_str)
        except ValueError as e:
            return str(e), 400

    occ.done_date = done_dt
    occ.status = "done"
    occ.performed_by = g.user.get("username")
    db.commit()

    add_new_planned_occurrence(db, ins, done_dt)
    log_event(
        "complete_occurrence",
        g.user.get("username"),
        {
            "inspection": ins.nazwa,
            "property": ins.nieruchomosc,
            "done_date": done_dt.isoformat(),
        },
        db_session=db,
    )
    return redirect(url_for("history", inspection_id=ins.id))


@app.route("/occurrence/<int:occ_id>/update", methods=["POST"])
@login_required
def update_occurrence(occ_id: int):
    db = get_db()
    occ = db.query(InspectionOccurrence).filter_by(id=occ_id).first()
    if not occ:
        return "Brak wystąpienia.", 404
    ins = db.query(Inspection).filter_by(id=occ.inspection_id).first()
    if not ins:
        return "Brak przeglądu.", 404

    prop_access = get_property_access_map(db)
    ins_dict = {
        "nazwa": ins.nazwa,
        "nieruchomosc": ins.nieruchomosc,
        "owner": ins.owner,
    }
    if not user_can_access(g.user, ins_dict, prop_access):
        return "Brak dostępu.", 403

    due_raw = (request.form.get("due_date") or "").strip()
    done_raw = (request.form.get("done_date") or "").strip()
    status_raw = (request.form.get("status") or occ.status).strip()
    note = (request.form.get("note") or "").strip()
    performer = (request.form.get("performed_by") or "").strip()

    try:
        occ.due_date = parse_date(due_raw) if due_raw else occ.due_date
    except ValueError as e:
        return str(e), 400

    if done_raw:
        try:
            occ.done_date = parse_date(done_raw)
        except ValueError as e:
            return str(e), 400
    elif status_raw != "done":
        occ.done_date = None

    allowed_status = {"planned", "done", "overdue"}
    occ.status = status_raw if status_raw in allowed_status else occ.status
    occ.note = note
    occ.performed_by = performer

    db.commit()
    log_event(
        "update_occurrence",
        g.user.get("username"),
        {
            "inspection": ins.nazwa,
            "property": ins.nieruchomosc,
            "occurrence_id": occ.id,
            "status": occ.status,
        },
        db_session=db,
    )
    return redirect(url_for("history", inspection_id=ins.id))


@app.route("/occurrence/<int:occ_id>/delete", methods=["POST"])
@login_required
def delete_occurrence(occ_id: int):
    db = get_db()
    occ = db.query(InspectionOccurrence).filter_by(id=occ_id).first()
    if not occ:
        return "Brak wystąpienia.", 404
    ins = db.query(Inspection).filter_by(id=occ.inspection_id).first()
    if not ins:
        return "Brak przeglądu.", 404

    prop_access = get_property_access_map(db)
    ins_dict = {
        "nazwa": ins.nazwa,
        "nieruchomosc": ins.nieruchomosc,
        "owner": ins.owner,
    }
    if not user_can_access(g.user, ins_dict, prop_access):
        return "Brak dostępu.", 403

    db.delete(occ)
    db.commit()
    log_event(
        "delete_occurrence",
        g.user.get("username"),
        {
            "inspection": ins.nazwa,
            "property": ins.nieruchomosc,
            "occurrence_id": occ_id,
        },
        db_session=db,
    )
    return redirect(url_for("history", inspection_id=ins.id))


@app.route("/history/<int:inspection_id>")
@login_required
def history(inspection_id: int):
    db = get_db()
    ins = db.query(Inspection).filter_by(id=inspection_id).first()
    if not ins:
        return "Nie znaleziono przeglądu.", 404
    prop_access = get_property_access_map(db)
    ins_dict = {
        "nazwa": ins.nazwa,
        "nieruchomosc": ins.nieruchomosc,
        "owner": ins.owner,
    }
    if not user_can_access(g.user, ins_dict, prop_access):
        return "Brak dostępu.", 403

    occurrences = (
        db.query(InspectionOccurrence)
        .filter_by(inspection_id=inspection_id)
        .order_by(InspectionOccurrence.due_date.desc())
        .all()
    )
    return render_template(
        "history.html",
        inspection=ins,
        occurrences=occurrences,
        today=date.today(),
    )


@app.route("/calendar")
@login_required
def calendar_view():
    db = get_db()
    ensure_occurrences_seed(db)
    prop_access = get_property_access_map(db)
    property_param = request.args.get("property", "").strip()
    year_param = request.args.get("year")

    inspections = db.query(Inspection).all()
    accessible_props = sorted(
        {
            ins.nieruchomosc
            for ins in inspections
            if user_can_access(
                g.user,
                {
                    "nazwa": ins.nazwa,
                    "nieruchomosc": ins.nieruchomosc,
                    "owner": ins.owner,
                },
                prop_access,
            )
        }
    )

    if not property_param:
        cards = []
        for prop in accessible_props:
            count_occ = (
                db.query(InspectionOccurrence)
                .join(Inspection)
                .filter(Inspection.nieruchomosc == prop)
                .count()
            )
            cards.append({"name": prop, "occ_count": count_occ})
        return render_template(
            "calendar.html",
            cards=cards,
            property_name=None,
            year=date.today().year,
            weeks=None,
            month_headers=None,
            rows=None,
            years=None,
        )

    property_name = property_param
    available_years = set()
    occurrences_all = (
        db.query(InspectionOccurrence, Inspection)
        .join(Inspection)
        .filter(Inspection.nieruchomosc == property_name)
        .all()
    )
    for occ, _ in occurrences_all:
        if occ.due_date:
            available_years.add(occ.due_date.isocalendar().year)
        if occ.done_date:
            available_years.add(occ.done_date.isocalendar().year)

    today_year = date.today().year
    if year_param:
        try:
            year = int(year_param)
        except ValueError:
            year = today_year
    else:
        if available_years:
            year = today_year if today_year in available_years else max(available_years)
        else:
            year = today_year

    year_start = date(year, 1, 1)
    year_end = date(year, 12, 31)
    first_week_start = year_start - timedelta(days=year_start.weekday())
    weeks = []
    week_start = first_week_start
    week_index = 1
    while week_start <= year_end:
        in_year_start = max(week_start, year_start)
        weeks.append(
            {
                "key": week_start.isoformat(),
                "label": week_index,
                "anchor": in_year_start,
            }
        )
        week_start += timedelta(days=7)
        week_index += 1

    month_headers = []
    current_label = None
    current_span = 0
    for w in weeks:
        label = w["anchor"].strftime("%b")
        if label != current_label:
            if current_label is not None:
                month_headers.append({"label": current_label, "span": current_span})
            current_label = label
            current_span = 1
        else:
            current_span += 1
    if current_label is not None:
        month_headers.append({"label": current_label, "span": current_span})

    events = []
    for occ, ins in occurrences_all:
        ins_dict = {
            "nazwa": ins.nazwa,
            "nieruchomosc": ins.nieruchomosc,
            "owner": ins.owner,
        }
        if not user_can_access(g.user, ins_dict, prop_access):
            continue
        if occ.status == "planned" and occ.due_date and occ.due_date.year == year:
            week_key = (
                occ.due_date - timedelta(days=occ.due_date.weekday())
            ).isoformat()
            events.append(
                {
                    "week_key": week_key,
                    "date": occ.due_date,
                    "name": ins.nazwa,
                    "property": ins.nieruchomosc,
                    "status": occ.status,
                    "occ_id": occ.id,
                    "inspection_id": ins.id,
                }
            )
        if occ.status == "done" and occ.done_date and occ.done_date.year == year:
            week_key = (
                occ.done_date - timedelta(days=occ.done_date.weekday())
            ).isoformat()
            events.append(
                {
                    "week_key": week_key,
                    "date": occ.done_date,
                    "name": ins.nazwa,
                    "property": ins.nieruchomosc,
                    "status": "done",
                    "occ_id": occ.id,
                    "inspection_id": ins.id,
                }
            )

    rows = {}
    today = date.today()
    for evt in events:
        key = evt["inspection_id"]
        if key not in rows:
            rows[key] = {
                "id": evt["inspection_id"],
                "name": evt["name"],
                "property": evt["property"],
                "markers": {},
            }
        status = evt["status"]
        if status != "done":
            if evt["date"] < today:
                status = "overdue"
        rows[key]["markers"][evt["week_key"]] = status

    rows_list = []
    for _, data in rows.items():
        rows_list.append(
            {
                "id": data["id"],
                "name": data["name"],
                "property": data["property"],
                "markers": data["markers"],
            }
        )
    rows_list.sort(key=lambda r: r["name"].lower())

    return render_template(
        "calendar.html",
        cards=None,
        property_name=property_name,
        year=year,
        weeks=weeks,
        month_headers=month_headers,
        rows=rows_list,
        years=sorted(available_years) if available_years else [year],
    )


@app.route("/admin/properties", methods=["GET", "POST"])
@login_required
def admin_properties():
    if not is_admin(g.user):
        return "Brak dostępu.", 403

    db = get_db()
    ensure_properties_seed(db)
    inspections = db.query(Inspection).all()
    prop_access = get_property_access_map(db)
    owners_map = compute_property_owner_map(
        [
            {
                "nieruchomosc": ins.nieruchomosc,
                "owner": ins.owner,
            }
            for ins in inspections
        ]
    )

    properties = []
    for prop in sorted({ins.nieruchomosc for ins in inspections if ins.nieruchomosc}):
        properties.append(
            {
                "name": prop,
                "slug": slugify_property(prop),
                "owner": owners_map.get(prop, ""),
                "shared_with": prop_access.get(prop, []),
                "segment": (
                    db.query(Property.segment).filter_by(name=prop).scalar() or ""
                ),
                "count": sum(1 for ins in inspections if ins.nieruchomosc == prop),
            }
        )

    if request.method == "POST":
        changes = []
        for prop in properties:
            new_owner = request.form.get(
                f"owner__{prop['slug']}", ""
            ).strip() or prop.get("owner", "")
            shared_with = [
                u.strip()
                for u in request.form.getlist(f"shared_with__{prop['slug']}")
                if u.strip()
            ]

            new_segment = request.form.get(f"segment__{prop['slug']}", "").strip()

            db.query(Inspection).filter(Inspection.nieruchomosc == prop["name"]).update(
                {"owner": new_owner, "segment": new_segment}
            )

            ensure_property_record(db, prop["name"], segment=new_segment)

            db.query(PropertyAccess).filter(
                PropertyAccess.nieruchomosc == prop["name"]
            ).delete()
            for u in shared_with:
                db.add(PropertyAccess(nieruchomosc=prop["name"], username=u))
            db.commit()
            changes.append(
                {
                    "property": prop["name"],
                    "owner": new_owner,
                    "shared_with": shared_with,
                }
            )

        g.property_access = get_property_access_map(db)
        log_event(
            "update_property_access",
            g.user["username"],
            {"properties": changes},
            db_session=db,
        )
        return redirect(url_for("admin_properties"))

    return render_template(
        "admin_properties.html",
        properties=properties,
        all_users=db.query(User).all(),
    )


@app.route("/admin/users", methods=["GET", "POST"])
@login_required
def admin_users():
    if not is_admin(g.user):
        return "Brak dostępu.", 403

    db = get_db()
    users = db.query(User).all()
    message = ""
    error = ""

    if request.method == "POST":
        action = request.form.get("action") or "update"
        username = (request.form.get("username") or "").strip()
        new_pin = (request.form.get("new_pin") or "").strip()

        if not username:
            error = "Wybierz użytkownika."
        else:
            user = db.query(User).filter_by(username=username).first()
            if not user:
                error = "Użytkownik nie istnieje."
            elif action == "update":
                if new_pin:
                    if not new_pin.isdigit() or len(new_pin) < 4:
                        error = "PIN musi składać się z co najmniej 4 cyfr."
                    else:
                        user.password = generate_password_hash(
                            new_pin, method="pbkdf2:sha256"
                        )
                        log_event(
                            "reset_pin",
                            g.user["username"],
                            {"target": username},
                            db_session=db,
                        )
                        message = f"Zmieniono PIN użytkownika {username}."
                db.commit()
            elif action == "test_email":
                if not user.email:
                    error = "Użytkownik nie ma ustawionego e-maila."
                else:
                    ok = send_direct_email(
                        [user.email],
                        "Test powiadomień Nadzorca",
                        "To jest testowy e-mail z aplikacji Nadzorca przeglądów.",
                    )
                    if ok:
                        message = f"Wysłano testowy e-mail do {user.email}."
                    else:
                        error = (
                            "Nie udało się wysłać maila (sprawdź konfigurację SMTP)."
                        )

    return render_template(
        "admin_users.html",
        users=users,
        message=message,
        error=error,
    )


@app.route("/admin/notifications", methods=["GET", "POST"])
@login_required
def admin_notifications():
    if not is_admin(g.user):
        return "Brak dostępu.", 403

    db = get_db()
    defaults = {
        "email_upcoming_subject": "Nadchodzące przeglądy",
        "email_upcoming_header": "Poniższe przeglądy zmieniły status na Nadchodzące:",
        "email_upcoming_line": "{name} — {property} (termin: {due})",
    }
    form = {k: get_setting_value(db, k, v) for k, v in defaults.items()}
    message = ""
    error = ""

    if request.method == "POST":
        for k in defaults.keys():
            form[k] = (request.form.get(k) or defaults[k]).strip()
            set_setting_value(db, k, form[k])
        message = "Zapisano szablon powiadomień."

    return render_template(
        "admin_notifications.html",
        form=form,
        message=message,
        error=error,
    )


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    db = get_db()
    user_obj = db.query(User).filter_by(username=g.user["username"]).first()
    if not user_obj:
        return redirect(url_for("logout"))

    errors = {}
    message = ""
    form = {
        "username": user_obj.username,
        "email": user_obj.email or "",
        "new_pin": "",
    }

    if request.method == "POST":
        form["username"] = (request.form.get("username") or "").strip()
        form["email"] = (request.form.get("email") or "").strip()
        form["new_pin"] = (request.form.get("new_pin") or "").strip()

        if not form["username"]:
            errors["username"] = "Nazwa użytkownika jest wymagana."
        else:
            exists = (
                db.query(User)
                .filter(User.username == form["username"], User.id != user_obj.id)
                .first()
            )
            if exists:
                errors["username"] = "Taka nazwa jest już używana."

        if form["email"]:
            if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", form["email"]):
                errors["email"] = "Podaj poprawny adres e-mail."

        if form["new_pin"]:
            if not form["new_pin"].isdigit() or len(form["new_pin"]) < 4:
                errors["new_pin"] = "PIN musi składać się z co najmniej 4 cyfr."

        if not errors:
            before_username = user_obj.username
            user_obj.username = form["username"]
            user_obj.email = form["email"] or None
            if form["new_pin"]:
                user_obj.password = generate_password_hash(
                    form["new_pin"], method="pbkdf2:sha256"
                )
            db.commit()
            session["username"] = user_obj.username
            log_event(
                "update_profile",
                user_obj.username,
                {"username_before": before_username, "email": user_obj.email},
                db_session=db,
            )
            message = "Zapisano zmiany."

    return render_template("profile.html", form=form, errors=errors, message=message)


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.get("user"):
        return redirect(url_for("index"))

    errors = {}
    username = (
        (request.form.get("username") or "").strip() if request.method == "POST" else ""
    )

    if request.method == "POST":
        password = request.form.get("password", "")
        if not username:
            errors["username"] = "Podaj nazwę użytkownika."
        if not password:
            errors["password"] = "Podaj hasło."

        user = find_user(username) if not errors else None
        if user:
            try:
                if check_password_hash(user.get("password", ""), password):
                    session["username"] = user["username"]
                    log_event(
                        "login",
                        user["username"],
                        {"ip": request.remote_addr, "next": request.args.get("next")},
                    )
                    next_url = request.args.get("next") or url_for("index")
                    return redirect(next_url)
            except ValueError:
                pass

        if request.method == "POST" and not errors:
            errors["password"] = "Nieprawidłowy login lub hasło."

    return render_template(
        "login.html",
        errors=errors,
        form={"username": username},
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    errors = {}
    form = {
        "username": "",
        "email": "",
        "password": "",
        "password_confirm": "",
    }

    if request.method == "POST":
        form["username"] = (request.form.get("username") or "").strip()
        form["email"] = (request.form.get("email") or "").strip()
        form["password"] = request.form.get("password", "")
        form["password_confirm"] = request.form.get("password_confirm", "")

        if not form["username"]:
            errors["username"] = "Podaj nazwę użytkownika."
        elif find_user(form["username"]):
            errors["username"] = "Użytkownik o takiej nazwie już istnieje."

        email_val = form["email"]
        if email_val:
            if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email_val):
                errors["email"] = "Podaj poprawny adres e-mail."

        if not form["password"]:
            errors["password"] = "Podaj PIN (co najmniej 4 cyfry)."
        elif not form["password"].isdigit():
            errors["password"] = "PIN może zawierać tylko cyfry."
        elif len(form["password"]) < 4:
            errors["password"] = "PIN musi mieć co najmniej 4 cyfry."

        if form["password"] != form["password_confirm"]:
            errors["password_confirm"] = "Hasła muszą być takie same."

        if not errors:
            db = get_db()
            new_u = User(
                username=form["username"],
                password=generate_password_hash(
                    form["password"], method="pbkdf2:sha256"
                ),
                role="user",
                email=form["email"],
            )
            db.add(new_u)
            db.commit()
            session["username"] = form["username"]
            log_event(
                "register", form["username"], {"ip": request.remote_addr}, db_session=db
            )
            return redirect(url_for("index"))

    return render_template("register.html", errors=errors, form=form)


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    debug_flag = os.getenv("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(debug=debug_flag)
