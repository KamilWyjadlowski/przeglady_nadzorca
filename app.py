from flask import Flask, render_template, request, redirect, url_for, session, g
import calendar
import json
import os
import re
import secrets
from datetime import date, datetime, timedelta
from functools import wraps
from math import ceil
from typing import List, Dict, Optional
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

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "przeglady")
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
    status = Column(String(32), nullable=False, default="planned")  # planned/done/overdue
    note = Column(Text)
    performed_by = Column(String(100))
    created_at = Column(DateTime, server_default=func.now())
    inspection = relationship("Inspection", backref="occurrences")


def parse_date(s: str) -> date:
    """
    Akceptuje format:
    - RRRR-MM-DD (ISO)
    - DD.MM.RRRR
    """
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


def add_months(d: date, months: int) -> date:
    year = d.year + (d.month - 1 + months) // 12
    month = (d.month - 1 + months) % 12 + 1
    day = min(d.day, calendar.monthrange(year, month)[1])
    return date(year, month, day)


def clean_empty_notes(text: str) -> str:
    text = text.strip()
    return text if text else "Brak uwag"


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
    """Zapewnia property_id dla każdej nieruchomości. Zwraca (changed, map, max_num)."""
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
    # zaktualizuj property_id w tabeli properties
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
        prop = Property(name=name_norm, property_id=property_id or None, segment=segment or None)
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
        form_token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        if form_token != g.csrf_token:
            return "Błędny token CSRF.", 400


@app.teardown_appcontext
def teardown_db(exc):
    db = getattr(g, "db", None)
    if db:
        db.close()


@app.context_processor
def inject_user():
    return {"current_user": g.get("user"), "csrf_token": g.get("csrf_token")}


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
    """Jeśli przegląd nie ma historii, twórz: wykonane (ostatnia_data) + planowane (kolejna_data)."""
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
    """Zwraca mapę nieruchomość -> właściciel (na podstawie pierwszego rekordu)."""
    owners: Dict[str, str] = {}
    for ins in inspections:
        prop = ins.get("nieruchomosc")
        if prop and prop not in owners:
            owners[prop] = ins.get("owner", "")
    return owners


def slugify_property(prop: str) -> str:
    """Prosty slug do użycia w nazwach pól formularza."""
    return (
        (prop or "")
        .replace(" ", "_")
        .replace("/", "_")
        .replace(".", "_")
        .replace(",", "_")
        .replace(":", "_")
    )


def user_can_manage_access(user: Dict, inspection: Dict) -> bool:
    """Kto może zmieniać ownera i dostęp: admin lub właściciel."""
    if is_admin(user):
        return True
    return inspection.get("owner") == user.get("username")


def add_new_planned_occurrence(db, ins: Inspection, done_date: date):
    """Po wykonaniu generuje nowe planowane wystąpienie i aktualizuje przegląd."""
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


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not g.get("user"):
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)

    return wrapper


@app.route("/")
@login_required
def index():
    db = get_db()
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
        if user_can_access(g.user, ins_dict, prop_access):
            ins_dict["idx"] = ins.id
            inspections.append(ins_dict)

    f_n = request.args.get("nieruchomosc", "").strip()
    f_name = request.args.get("nazwa", "").strip()
    f_status = request.args.get("status", "").strip()
    f_uwagi = request.args.get("uwagi", "").strip()
    f_segment = request.args.get("segment", "").strip()
    f_q = request.args.get("q", "").strip().lower()
    sort_by = request.args.get("sort", "default")
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    per_page = 15

    filtered = []
    for idx, ins in enumerate(inspections):
        opis = (ins.get("opis") or "").strip()
        ok = True

        if f_n and ins.get("nieruchomosc") != f_n:
            ok = False
        if f_name and ins.get("nazwa") != f_name:
            ok = False
        if f_status and ins.get("status") != f_status:
            ok = False
        if f_uwagi == "tak" and opis.lower() in ("", "brak uwag"):
            ok = False
        if f_uwagi == "nie" and opis.lower() not in ("", "brak uwag"):
            ok = False
        if f_segment and ins.get("segment") != f_segment:
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

    used_properties = get_unique(inspections, "nieruchomosc")
    used_names = get_unique(inspections, "nazwa")
    used_status = get_unique(inspections, "status")
    used_segments = get_unique(inspections, "segment")

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

    total = len(filtered)
    total_pages = max(1, ceil(total / per_page)) if total else 1
    if page > total_pages:
        page = total_pages
    start = (page - 1) * per_page
    end = start + per_page
    page_items = filtered[start:end]

    args_dict = request.args.to_dict()

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
        page=page,
        total_pages=total_pages,
        prev_url=prev_url,
        next_url=next_url,
        total_items=total,
        per_page=per_page,
    )


def extract_form():
    """Czyści pobieranie danych z formularza i zwraca słownik."""
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
    """Walidacja formularza. Zwraca errors{} lub pusty słownik."""
    errors = {}

    if not form["nazwa"]:
        errors["nazwa"] = "Nazwa jest wymagana."

    if not form["nieruchomosc"]:
        errors["nieruchomosc"] = "Nieruchomość jest wymagana."

    if not form["segment"]:
        errors["segment"] = "Wybierz segment — Detal lub Hurt."

    email = form.get("email", "")
    if email:
        if not re.match(r"^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", email):
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
    """Zbiera mapę firma -> kontakt do autouzupełniania."""
    result = {}
    for ins in inspections:
        firma = ins.get("firma")
        if firma:
            result[firma] = {
                "telefon": ins.get("telefon", ""),
                "email": ins.get("email", ""),
            }
    return result


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
            # zaktualizuj najbliższe planowane (jeśli jest) do nowej daty
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

    # Usuń historię/wystąpienia powiązane z przeglądem, by uniknąć błędów FK
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
    ins_dict = {"nazwa": ins.nazwa, "nieruchomosc": ins.nieruchomosc, "owner": ins.owner}
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
        {"inspection": ins.nazwa, "property": ins.nieruchomosc, "done_date": done_dt.isoformat()},
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
    ins_dict = {"nazwa": ins.nazwa, "nieruchomosc": ins.nieruchomosc, "owner": ins.owner}
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
    """
    Widok kalendarza:
    - bez parametru property pokazuje kafelki nieruchomości, do których user ma dostęp
    - z parametrem ?property=XYZ pokazuje tygodniowy kalendarz wystąpień dla danej nieruchomości
    """
    db = get_db()
    ensure_occurrences_seed(db)
    prop_access = get_property_access_map(db)
    property_param = request.args.get("property", "").strip()
    year_param = request.args.get("year")

    # Lista dostępnych nieruchomości dla usera
    inspections = db.query(Inspection).all()
    accessible_props = sorted(
        {
            ins.nieruchomosc
            for ins in inspections
            if user_can_access(
                g.user,
                {"nazwa": ins.nazwa, "nieruchomosc": ins.nieruchomosc, "owner": ins.owner},
                prop_access,
            )
        }
    )

    # Jeśli nie wybrano nieruchomości – pokaż kafelki
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
            months=None,
            rows=None,
            years=None,
        )

    # Widok konkretnej nieruchomości
    property_name = property_param
    # dostępne lata z terminów/daty wykonania
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

    weeks = []
    months = []
    for w in range(1, 54):
        try:
            d = date.fromisocalendar(year, w, 1)
            weeks.append(w)
            months.append(d.strftime("%b"))
        except ValueError:
            continue

    events = []
    for occ, ins in occurrences_all:
        ins_dict = {"nazwa": ins.nazwa, "nieruchomosc": ins.nieruchomosc, "owner": ins.owner}
        if not user_can_access(g.user, ins_dict, prop_access):
            continue
        if occ.status == "planned" and occ.due_date:
            iso_year, iso_week, _ = occ.due_date.isocalendar()
            if iso_year == year:
                events.append(
                    {
                        "week": iso_week,
                        "year": iso_year,
                        "date": occ.due_date,
                        "name": ins.nazwa,
                        "property": ins.nieruchomosc,
                        "status": occ.status,
                        "occ_id": occ.id,
                    }
                )
        if occ.status == "done" and occ.done_date:
            iso_year, iso_week, _ = occ.done_date.isocalendar()
            if iso_year == year:
                events.append(
                    {
                        "week": iso_week,
                        "year": iso_year,
                        "date": occ.done_date,
                        "name": ins.nazwa,
                        "property": ins.nieruchomosc,
                        "status": "done",
                        "occ_id": occ.id,
                    }
                )

    # budujemy wiersze: każdy przegląd -> znaczniki w tygodniach
    rows = {}
    today = date.today()
    for evt in events:
        key = evt["name"]
        if key not in rows:
            rows[key] = {"full_name": evt["name"], "markers": {}}
        status = evt["status"]
        if status != "done":
            if evt["date"] < today:
                status = "overdue"
        rows[key]["markers"][evt["week"]] = status

    rows_list = []
    for name, data in rows.items():
        rows_list.append({"name": name, "markers": data["markers"]})
    rows_list.sort(key=lambda r: r["name"].lower())

    return render_template(
        "calendar.html",
        cards=None,
        property_name=property_name,
        year=year,
        weeks=weeks,
        months=months,
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
                "segment": (db.query(Property.segment).filter_by(name=prop).scalar() or ""),
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
        username = (request.form.get("username") or "").strip()
        new_pin = (request.form.get("new_pin") or "").strip()

        if not username:
            error = "Wybierz użytkownika."
        elif not new_pin:
            error = "Podaj nowy PIN."
        elif not new_pin.isdigit() or len(new_pin) < 4:
            error = "PIN musi składać się z co najmniej 4 cyfr."
        else:
            user = db.query(User).filter_by(username=username).first()
            if not user:
                error = "Użytkownik nie istnieje."
            else:
                user.password = generate_password_hash(new_pin, method="pbkdf2:sha256")
                db.commit()
                log_event(
                    "reset_pin",
                    g.user["username"],
                    {"target": username},
                    db_session=db,
                )
                message = f"Zmieniono PIN użytkownika {username}."

    return render_template(
        "admin_users.html",
        users=users,
        message=message,
        error=error,
    )


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
        "password": "",
        "password_confirm": "",
    }

    if request.method == "POST":
        form["username"] = (request.form.get("username") or "").strip()
        form["password"] = request.form.get("password", "")
        form["password_confirm"] = request.form.get("password_confirm", "")

        if not form["username"]:
            errors["username"] = "Podaj nazwę użytkownika."
        elif find_user(form["username"]):
            errors["username"] = "Użytkownik o takiej nazwie już istnieje."

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
