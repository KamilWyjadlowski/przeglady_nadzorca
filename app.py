from flask import Flask, render_template, request, redirect, url_for, session, g
import json
import os
import re
from datetime import date, datetime, timedelta
from functools import wraps
from math import ceil
from typing import List, Dict, Optional
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
DATA_FILE = "przeglady.json"
USERS_FILE = "users.json"
PROPERTY_ACCESS_FILE = "property_access.json"
AUDIT_FILE = "audit.log"

if not os.path.exists(DATA_FILE):
    if os.path.exists("przeglady.json"):
        with open("przeglady.json", "r", encoding="utf-8") as src:
            with open(DATA_FILE, "w", encoding="utf-8") as dst:
                dst.write(src.read())
    else:
        with open(DATA_FILE, "w", encoding="utf-8") as dst:
            dst.write("[]")

if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w", encoding="utf-8") as dst:
        dst.write("[]")

if not os.path.exists(PROPERTY_ACCESS_FILE):
    with open(PROPERTY_ACCESS_FILE, "w", encoding="utf-8") as dst:
        dst.write("{}")

if not os.path.exists(AUDIT_FILE):
    with open(AUDIT_FILE, "w", encoding="utf-8") as dst:
        dst.write("")


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


import calendar
from datetime import date


def add_months(d: date, months: int) -> date:
    year = d.year + (d.month - 1 + months) // 12
    month = (d.month - 1 + months) % 12 + 1
    day = min(d.day, calendar.monthrange(year, month)[1])
    return date(year, month, day)


def clean_empty_notes(text: str) -> str:
    text = text.strip()
    return text if text else "Brak uwag"


def normalize_phone(phone: str) -> str:
    cleaned = re.sub(r"[\\s\\-()]", "", phone)
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


def log_event(action: str, user: str, details: Dict):
    """Zapis logu audytowego w formacie JSON Lines z retencją 4 miesięcy."""
    entry = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "action": action,
        "user": user,
        "details": details,
    }

    cutoff = datetime.utcnow() - timedelta(days=120)
    kept = []
    if os.path.exists(AUDIT_FILE):
        try:
            with open(AUDIT_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        obj = json.loads(line)
                        ts = obj.get("ts", "")
                        dt = datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(
                            tzinfo=None
                        )
                        if dt >= cutoff:
                            kept.append(obj)
                    except Exception:
                        pass
        except Exception:
            pass

    kept.append(entry)

    try:
        with open(AUDIT_FILE, "w", encoding="utf-8") as f:
            for obj in kept:
                f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    except Exception:
        pass


def load_inspections() -> List[Dict]:
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            for ins in data:
                if "shared_with" not in ins or not isinstance(
                    ins.get("shared_with"), list
                ):
                    ins["shared_with"] = []
                if "property_id" not in ins:
                    ins["property_id"] = ""
            changed, _, _ = ensure_property_ids(data)
            if changed:
                save_inspections(data)
            return data
    except FileNotFoundError:
        return []


def save_inspections(data: List[Dict]) -> None:
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def filter_by_owner(inspections: List[Dict], username: str) -> List[Dict]:
    if not username:
        return []
    return [ins for ins in inspections if ins.get("owner") == username]


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


def load_users() -> List[Dict]:
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return []


def save_users(users: List[Dict]) -> None:
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)


def load_property_access() -> Dict[str, List[str]]:
    try:
        with open(PROPERTY_ACCESS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return {}
            clean = {}
            for prop, users in data.items():
                if isinstance(users, list):
                    clean[prop] = [u for u in users if u]
            return clean
    except FileNotFoundError:
        return {}


def save_property_access(data: Dict[str, List[str]]) -> None:
    with open(PROPERTY_ACCESS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def find_user(username: str) -> Optional[Dict]:
    username = (username or "").strip()
    for user in load_users():
        if user.get("username") == username:
            return user
    return None


def get_property_access() -> Dict[str, List[str]]:
    if not hasattr(g, "property_access"):
        g.property_access = load_property_access()
    return g.property_access


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


def is_admin(user: Optional[Dict]) -> bool:
    return bool(user) and user.get("role") == "admin"


def user_can_access(user: Dict, inspection: Dict) -> bool:
    """Czy użytkownik może zobaczyć/edytować przegląd."""
    if is_admin(user):
        return True
    username = user.get("username")
    if inspection.get("owner") == username:
        return True

    prop_access = get_property_access()
    if username in prop_access.get(inspection.get("nieruchomosc"), []):
        return True

    return username in inspection.get("shared_with", [])


def user_can_manage_access(user: Dict, inspection: Dict) -> bool:
    """Kto może zmieniać ownera i dostęp: admin lub właściciel."""
    if is_admin(user):
        return True
    return inspection.get("owner") == user.get("username")


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not g.get("user"):
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)

    return wrapper


@app.before_request
def load_logged_in_user():
    username = session.get("username")
    g.user = find_user(username) if username else None


@app.context_processor
def inject_user():
    return {"current_user": g.get("user")}


@app.route("/")
@login_required
def index():
    username = g.user["username"]
    all_inspections = load_inspections()
    inspections = []
    for idx, ins in enumerate(all_inspections):
        if not user_can_access(g.user, ins):
            continue
        row = ins.copy()
        row["idx"] = idx
        inspections.append(row)

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
            row["idx"] = idx
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
        property_access=get_property_access(),
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
    username = g.user["username"]
    inspections = [i for i in load_inspections() if user_can_access(g.user, i)]
    prop_access = get_property_access()
    existing_all = load_inspections()
    prop_ids_map, max_pid = property_id_state(existing_all)
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
            "owner": username,
            "property_shared_with": [],
        }

    errors = validate_form(form) if request.method == "POST" else {}

    if request.method == "POST" and not errors:
        freq = int(form["czestotliwosc_miesiace"])
        next_dt, status = compute_next_and_status(form["ostatnia_data"], freq)

        prop_name = normalize_property_name(form["nieruchomosc"])
        if prop_name in prop_ids_map:
            pid = prop_ids_map[prop_name]
        else:
            max_pid += 1
            pid = f"P{max_pid:04d}"
            prop_ids_map[prop_name] = pid

        new_item = {
            "nazwa": form["nazwa"],
            "nieruchomosc": prop_name,
            "property_id": pid,
            "ostatnia_data": form["ostatnia_data"],
            "czestotliwosc_miesiace": freq,
            "kolejna_data": next_dt,
            "status": status,
            "opis": clean_empty_notes(form["opis"]),
            "firma": form["firma"],
            "telefon": form["telefon"],
            "email": form["email"],
            "segment": form["segment"],
            "owner": form.get("owner") or username,
            "shared_with": [],
        }

        if not is_admin(g.user):
            new_item["owner"] = username
            new_item["shared_with"] = []
            form["property_shared_with"] = []

        existing_all.append(new_item)
        save_inspections(existing_all)

        if is_admin(g.user):
            prop_access[new_item["nieruchomosc"]] = form.get("property_shared_with", [])
            save_property_access(prop_access)
        log_event(
            "add_inspection",
            username,
            {
                "property": new_item["nieruchomosc"],
                "property_id": new_item.get("property_id", ""),
                "name": new_item["nazwa"],
                "owner": new_item["owner"],
            },
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
        all_users=load_users(),
        property_access=prop_access,
    )


@app.route("/edit/<int:idx>", methods=["GET", "POST"])
@login_required
def edit(idx: int):
    username = g.user["username"]
    all_inspections = load_inspections()
    accessible = [i for i in all_inspections if user_can_access(g.user, i)]
    prop_access = get_property_access()

    if not (0 <= idx < len(all_inspections)):
        return "Nie znaleziono przeglądu.", 404

    ins = all_inspections[idx]
    if not user_can_access(g.user, ins):
        return "Brak dostępu do tego przeglądu.", 403

    if request.method == "POST":
        form = extract_form()
        errors = validate_form(form)

        if not errors:
            freq = int(form["czestotliwosc_miesiace"])
            next_dt, status = compute_next_and_status(form["ostatnia_data"], freq)
            before = ins.copy()

            new_owner = form.get("owner") or ins.get("owner") or username
            if not is_admin(g.user):
                new_owner = ins.get("owner", username)
                form["shared_with"] = ins.get("shared_with", [])
                form["property_shared_with"] = prop_access.get(
                    ins.get("nieruchomosc"), []
                )

            ins.update(
                {
                    "nazwa": form["nazwa"],
                    "nieruchomosc": normalize_property_name(form["nieruchomosc"]),
                    "property_id": ins.get("property_id", ""),
                    "ostatnia_data": form["ostatnia_data"],
                    "czestotliwosc_miesiace": freq,
                    "kolejna_data": next_dt,
                    "status": status,
                    "opis": clean_empty_notes(form["opis"]),
                    "firma": form["firma"],
                    "telefon": form["telefon"],
                    "email": form["email"],
                    "segment": form["segment"],
                    "owner": new_owner,
                    "shared_with": [],
                }
            )

            all_inspections[idx] = ins
            save_inspections(all_inspections)

            if is_admin(g.user):
                prop_access.pop(ins.get("nieruchomosc"), None)
                prop_access[ins["nieruchomosc"]] = form.get("property_shared_with", [])
                save_property_access(prop_access)
            log_event(
                "edit_inspection",
                username,
                {
                    "property": ins["nieruchomosc"],
                    "property_id": ins.get("property_id", ""),
                    "name": ins["nazwa"],
                    "owner_before": before.get("owner"),
                    "owner_after": ins.get("owner"),
                },
            )
            return redirect(url_for("index"))

    else:
        form = {
            "nazwa": ins.get("nazwa", ""),
            "nieruchomosc": ins.get("nieruchomosc", ""),
            "property_id": ins.get("property_id", ""),
            "ostatnia_data": ins.get("ostatnia_data", ""),
            "czestotliwosc_miesiace": str(ins.get("czestotliwosc_miesiace", "")),
            "opis": ins.get("opis", ""),
            "firma": ins.get("firma", ""),
            "telefon": ins.get("telefon", ""),
            "email": ins.get("email", ""),
            "segment": ins.get("segment", ""),
            "owner": ins.get("owner", username),
            "shared_with": ins.get("shared_with", []),
            "property_shared_with": prop_access.get(ins.get("nieruchomosc"), []),
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
        all_users=load_users(),
        property_access=prop_access,
    )


@app.route("/delete/<int:idx>", methods=["POST"])
@login_required
def delete(idx: int):
    username = g.user["username"]
    all_inspections = load_inspections()

    if not (0 <= idx < len(all_inspections)):
        return "Nie znaleziono przeglądu.", 404

    ins = all_inspections[idx]
    if not user_can_access(g.user, ins):
        return "Brak dostępu do tego przeglądu.", 403

    del all_inspections[idx]
    save_inspections(all_inspections)
    log_event(
        "delete_inspection",
        username,
        {
            "property": ins.get("nieruchomosc"),
            "property_id": ins.get("property_id", ""),
            "name": ins.get("nazwa"),
            "owner": ins.get("owner"),
        },
    )
    return redirect(url_for("index"))


@app.route("/admin/properties", methods=["GET", "POST"])
@login_required
def admin_properties():
    if not is_admin(g.user):
        return "Brak dostępu.", 403

    inspections = load_inspections()
    prop_access = get_property_access()
    owners_map = compute_property_owner_map(inspections)

    properties = []
    for prop in sorted(
        {ins.get("nieruchomosc", "") for ins in inspections if ins.get("nieruchomosc")}
    ):
        properties.append(
            {
                "name": prop,
                "slug": slugify_property(prop),
                "owner": owners_map.get(prop, ""),
                "shared_with": prop_access.get(prop, []),
                "count": sum(
                    1 for ins in inspections if ins.get("nieruchomosc") == prop
                ),
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

            for ins in inspections:
                if ins.get("nieruchomosc") == prop["name"]:
                    ins["owner"] = new_owner

            prop_access[prop["name"]] = shared_with
            changes.append(
                {
                    "property": prop["name"],
                    "owner": new_owner,
                    "shared_with": shared_with,
                }
            )

        save_inspections(inspections)
        save_property_access(prop_access)
        g.property_access = prop_access
        log_event(
            "update_property_access",
            g.user["username"],
            {"properties": changes},
        )
        return redirect(url_for("admin_properties"))

    return render_template(
        "admin_properties.html",
        properties=properties,
        all_users=load_users(),
    )


@app.route("/admin/users", methods=["GET", "POST"])
@login_required
def admin_users():
    if not is_admin(g.user):
        return "Brak dostępu.", 403

    users = load_users()
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
            user = find_user(username)
            if not user:
                error = "Użytkownik nie istnieje."
            else:
                for u in users:
                    if u.get("username") == username:
                        u["password"] = generate_password_hash(
                            new_pin, method="pbkdf2:sha256"
                        )
                save_users(users)
                log_event(
                    "reset_pin",
                    g.user["username"],
                    {"target": username},
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
            users = load_users()
            users.append(
                {
                    "username": form["username"],
                    "password": generate_password_hash(
                        form["password"], method="pbkdf2:sha256"
                    ),
                    "role": "user",
                }
            )
            save_users(users)
            session["username"] = form["username"]
            log_event("register", form["username"], {"ip": request.remote_addr})
            return redirect(url_for("index"))

    return render_template("register.html", errors=errors, form=form)


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
