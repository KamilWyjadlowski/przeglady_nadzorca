from flask import Flask, render_template, request, redirect, url_for
import json
import os
from datetime import date
from typing import List, Dict

app = Flask(__name__)

DATA_FILE = "/var/tmp/przeglady.json"

if not os.path.exists(DATA_FILE):
    if os.path.exists("przeglady.json"):
        with open("przeglady.json", "r", encoding="utf-8") as src:
            with open(DATA_FILE, "w", encoding="utf-8") as dst:
                dst.write(src.read())
    else:
        with open(DATA_FILE, "w", encoding="utf-8") as dst:
            dst.write("[]")


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
            return json.load(f)
    except FileNotFoundError:
        return []


def save_inspections(data: List[Dict]) -> None:
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


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


@app.route("/")
def index():
    inspections = load_inspections()

    # FILTRY
    f_n = request.args.get("nieruchomosc", "").strip()
    f_name = request.args.get("nazwa", "").strip()
    f_status = request.args.get("status", "").strip()
    f_uwagi = request.args.get("uwagi", "").strip()

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

        if ok:
            row = ins.copy()
            row["idx"] = idx
            filtered.append(row)

    # LISTY DO FILTRÓW — TYLKO Z PRZEFILTROWANYCH
    used_properties = get_unique(filtered, "nieruchomosc")
    used_names = get_unique(filtered, "nazwa")
    used_status = get_unique(filtered, "status")

    return render_template(
        "index.html",
        inspections=filtered,
        used_properties=used_properties,
        used_names=used_names,
        used_status=used_status,
        used_uwagi=["tak", "nie"],
    )


def extract_form():
    """Czyści pobieranie danych z formularza i zwraca słownik."""
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
    }


def validate_form(form):
    """Walidacja formularza. Zwraca errors{} lub pusty słownik."""
    errors = {}

    if not form["nazwa"]:
        errors["nazwa"] = "Nazwa jest wymagana."

    if not form["nieruchomosc"]:
        errors["nieruchomosc"] = "Nieruchomość jest wymagana."

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
def add():
    inspections = load_inspections()
    form = (
        extract_form()
        if request.method == "POST"
        else {
            key: ""
            for key in [
                "nazwa",
                "nieruchomosc",
                "ostatnia_data",
                "czestotliwosc_miesiace",
                "opis",
                "firma",
                "telefon",
                "email",
            ]
        }
    )

    errors = validate_form(form) if request.method == "POST" else {}

    if request.method == "POST" and not errors:
        freq = int(form["czestotliwosc_miesiace"])
        next_dt, status = compute_next_and_status(form["ostatnia_data"], freq)

        inspections.append(
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
            }
        )

        save_inspections(inspections)
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
    )


@app.route("/edit/<int:idx>", methods=["GET", "POST"])
def edit(idx: int):
    inspections = load_inspections()

    if not (0 <= idx < len(inspections)):
        return "Nie znaleziono przeglądu.", 404

    ins = inspections[idx]

    if request.method == "POST":
        form = extract_form()
        errors = validate_form(form)

        if not errors:
            freq = int(form["czestotliwosc_miesiace"])
            next_dt, status = compute_next_and_status(form["ostatnia_data"], freq)

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
                }
            )

            save_inspections(inspections)
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
        }
        errors = {}

    return render_template(
        "form.html",
        mode="edit",
        errors=errors,
        form=form,
        used_names=get_unique(inspections, "nazwa"),
        used_properties=get_unique(inspections, "nieruchomosc"),
        used_companies=get_unique(inspections, "firma"),
        company_contacts=build_company_contacts(inspections),
    )


@app.route("/delete/<int:idx>", methods=["POST"])
def delete(idx: int):
    inspections = load_inspections()

    if not (0 <= idx < len(inspections)):
        return "Nie znaleziono przeglądu.", 404

    del inspections[idx]
    save_inspections(inspections)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
