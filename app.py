from flask import Flask, render_template, request, redirect, url_for, session, g
import json
import os
from datetime import date
from functools import wraps
from typing import List, Dict, Optional
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
DATA_FILE = "przeglady.json"
USERS_FILE = "users.json"
PROPERTY_ACCESS_FILE = "property_access.json"

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


def load_inspections() -> List[Dict]:
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            for ins in data:
                if "shared_with" not in ins or not isinstance(
                    ins.get("shared_with"), list
                ):
                    ins["shared_with"] = []
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
    # dostęp na poziomie nieruchomości
    prop_access = get_property_access()
    if username in prop_access.get(inspection.get("nieruchomosc"), []):
        return True
    # stary mechanizm per przegląd (zachowany, ale nie używany w UI)
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
        row["idx"] = idx  # global index w pliku
        inspections.append(row)

    # FILTRY
    f_n = request.args.get("nieruchomosc", "").strip()
    f_name = request.args.get("nazwa", "").strip()
    f_status = request.args.get("status", "").strip()
    f_uwagi = request.args.get("uwagi", "").strip()
    # NOWE – filtr po segmencie (Detal / Hurt)
    f_segment = request.args.get("segment", "").strip()

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
        # NOWE – filtr po segmencie
        if f_segment and ins.get("segment") != f_segment:
            ok = False

        if ok:
            row = ins.copy()
            row["idx"] = idx
            filtered.append(row)

    # LISTY DO FILTRÓW — TYLKO Z PRZEFILTROWANYCH
    used_properties = get_unique(filtered, "nieruchomosc")
    used_names = get_unique(filtered, "nazwa")
    used_status = get_unique(filtered, "status")
    used_segments = get_unique(filtered, "segment")

    # SORTOWANIE:
    # 1. nieruchomość alfabetycznie
    # 2. status (Zaległy -> Nadchodzące -> Aktualne)
    # 3. kolejna_data rosnąco
    # 4. nazwa przeglądu alfabetycznie
    status_order = {
        "Zaległy": 0,
        "Nadchodzące": 1,
        "Aktualne": 2,
    }

    def safe_date(d):
        """Zamienia '2025-12-10' na date, przy braku/śmieciu daje bardzo odległą przyszłość."""
        try:
            return date.fromisoformat(d)
        except Exception:
            return date(9999, 12, 31)

    filtered.sort(
        key=lambda ins: (
            ins.get("nieruchomosc", ""),
            status_order.get(ins.get("status"), 99),
            safe_date(ins.get("kolejna_data")),
            ins.get("nazwa", ""),
        )
    )

    return render_template(
        "index.html",
        inspections=filtered,
        used_properties=used_properties,
        used_names=used_names,
        used_status=used_status,
        used_uwagi=["tak", "nie"],
        used_segments=used_segments,
        property_access=get_property_access(),
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

        new_item = {
            "nazwa": form["nazwa"],
            "nieruchomosc": normalize_property_name(form["nieruchomosc"]),
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

        all_inspections = load_inspections()
        all_inspections.append(new_item)
        save_inspections(all_inspections)

        if is_admin(g.user):
            prop_access[new_item["nieruchomosc"]] = form.get("property_shared_with", [])
            save_property_access(prop_access)
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

            new_owner = form.get("owner") or ins.get("owner") or username
            if not is_admin(g.user):
                # zwykły użytkownik nie może zmieniać ownera ani udostępnień
                new_owner = ins.get("owner", username)
                form["shared_with"] = ins.get("shared_with", [])
                form["property_shared_with"] = prop_access.get(
                    ins.get("nieruchomosc"), []
                )

            ins.update(
                {
                    "nazwa": form["nazwa"],
                    "nieruchomosc": normalize_property_name(form["nieruchomosc"]),
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
            return redirect(url_for("index"))

    else:
        form = {
            "nazwa": ins.get("nazwa", ""),
            "nieruchomosc": ins.get("nieruchomosc", ""),
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
    for prop in sorted({ins.get("nieruchomosc", "") for ins in inspections if ins.get("nieruchomosc")}):
        properties.append(
            {
                "name": prop,
                "slug": slugify_property(prop),
                "owner": owners_map.get(prop, ""),
                "shared_with": prop_access.get(prop, []),
                "count": sum(1 for ins in inspections if ins.get("nieruchomosc") == prop),
            }
        )

    if request.method == "POST":
        for prop in properties:
            shared_with = [
                u.strip() for u in request.form.getlist(f"shared_with__{prop['slug']}") if u.strip()
            ]

            # zapisz udostępnienia (właściciela nie zmieniamy tutaj)
            prop_access[prop["name"]] = shared_with

        save_inspections(inspections)
        save_property_access(prop_access)
        g.property_access = prop_access
        return redirect(url_for("admin_properties"))

    return render_template(
        "admin_properties.html",
        properties=properties,
        all_users=load_users(),
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
                    next_url = request.args.get("next") or url_for("index")
                    return redirect(next_url)
            except ValueError:
                # np. nieobsługiwany format hash -> potraktuj jako błędne hasło
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
            return redirect(url_for("index"))

    return render_template("register.html", errors=errors, form=form)


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
