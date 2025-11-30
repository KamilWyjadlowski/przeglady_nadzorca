from flask import Flask, render_template, request, redirect, url_for
import json
from datetime import date
from typing import List, Dict

app = Flask(__name__)

import os

DATA_FILE = "/var/tmp/przeglady.json"

# jeśli plik nie istnieje (pierwsze uruchomienie) – skopiuj wersję z repo
if not os.path.exists(DATA_FILE):
    if os.path.exists("przeglady.json"):
        with open("przeglady.json", "r", encoding="utf-8") as src:
            with open(DATA_FILE, "w", encoding="utf-8") as dst:
                dst.write(src.read())
    else:
        # brak pliku w repo -> utwórz pustą listę
        with open(DATA_FILE, "w", encoding="utf-8") as dst:
            dst.write("[]")


# ---------- LOGIKA (z konsolowej wersji) ----------


def parse_date(user_input: str) -> date:
    """
    Przyjmuje datę w formacie:
    - RRRR-MM-DD  (np. 2025-08-12)
    - albo DD.MM.RRRR (np. 12.08.2025)
    Zwraca obiekt date albo rzuca ValueError.
    """
    s = user_input.strip()

    if "." in s:
        parts = s.split(".")
        if len(parts) == 3:
            day_str, month_str, year_str = [p.strip() for p in parts]
            try:
                day = int(day_str)
                month = int(month_str)
                year = int(year_str)
                return date(year, month, day)
            except ValueError:
                pass

    try:
        return date.fromisoformat(s)
    except ValueError:
        raise ValueError(
            f"Nieprawidłowy format daty: '{user_input}'. "
            "Użyj RRRR-MM-DD (np. 2025-08-12) albo DD.MM.RRRR (np. 12.08.2025)."
        )


def normalize_property_name(raw: str) -> str:
    parts = raw.strip().split()
    return " ".join(p.capitalize() for p in parts)


def add_months(d: date, months: int) -> date:
    month = d.month - 1 + months
    year = d.year + month // 12
    month = month % 12 + 1

    days_in_month = [
        31,
        29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28,
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ][month - 1]

    day = min(d.day, days_in_month)
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


def save_inspections(inspections: List[Dict]) -> None:
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(inspections, f, ensure_ascii=False, indent=2)


def compute_next_and_status(last_date_str: str, freq_months: int) -> tuple[str, str]:
    last = parse_date(last_date_str)
    next_dt = add_months(last, freq_months)
    today = date.today()

    if next_dt < today:
        status = "Zaległy"
    elif (next_dt - today).days <= 30:
        status = "Nadchodzące"
    else:
        status = "Aktualne"

    return next_dt.isoformat(), status


def get_unique_properties(inspections: List[Dict]) -> List[str]:
    props = {
        ins.get("nieruchomosc", "") for ins in inspections if ins.get("nieruchomosc")
    }
    return sorted(props)


def get_unique_names(inspections: List[Dict]) -> List[str]:
    names = {ins.get("nazwa", "") for ins in inspections if ins.get("nazwa")}
    return sorted(names)


# ---------- ROUTES (widoki www) ----------


@app.route("/")
@app.route("/")
@app.route("/")
@app.route("/")
@app.route("/")
@app.route("/")
@app.route("/")
@app.route("/")
@app.route("/")
@app.route("/")
@app.route("/")
def index():
    inspections = load_inspections()

    # przygotowujemy WIERSZE z prawdziwymi indeksami
    rows = []
    for i, ins in enumerate(inspections):
        row = ins.copy()
        row["idx"] = i  # PRAWDZIWY indeks w JSON-ie
        rows.append(row)

    # jeśli chcesz — tutaj możesz robić sortowanie rows
    # rows = sorted(rows, key=lambda x: x["nazwa"])

    return render_template("index.html", inspections=rows)


@app.route("/add", methods=["GET", "POST"])
@app.route("/add", methods=["GET", "POST"])
@app.route("/add", methods=["GET", "POST"])
@app.route("/add", methods=["GET", "POST"])
@app.route("/add", methods=["GET", "POST"])
@app.route("/add", methods=["GET", "POST"])
def add():
    inspections = load_inspections()
    errors = {}

    # dane formularza – startowo puste
    form_data = {
        "nazwa": "",
        "nieruchomosc": "",
        "ostatnia_data": "",
        "czestotliwosc_miesiace": "",
        "opis": "",
        "firma": "",
        "telefon": "",
        "email": "",
    }

    if request.method == "POST":
        # zbieranie danych z formularza
        form_data["nazwa"] = request.form.get("nazwa", "").strip()
        form_data["nieruchomosc"] = request.form.get("nieruchomosc", "").strip()
        form_data["ostatnia_data"] = request.form.get("ostatnia_data", "").strip()
        form_data["czestotliwosc_miesiace"] = request.form.get(
            "czestotliwosc_miesiace", ""
        ).strip()
        form_data["opis"] = request.form.get("opis", "").strip()
        form_data["firma"] = request.form.get("firma", "").strip()
        form_data["telefon"] = request.form.get("telefon", "").strip()
        form_data["email"] = request.form.get("email", "").strip()

        # --- Walidacja ---

        if not form_data["nazwa"]:
            errors["nazwa"] = "Nazwa jest wymagana."

        if not form_data["nieruchomosc"]:
            errors["nieruchomosc"] = "Nieruchomość jest wymagana."

        try:
            parse_date(form_data["ostatnia_data"])
        except ValueError as e:
            errors["ostatnia_data"] = str(e)

        try:
            freq = int(form_data["czestotliwosc_miesiace"])
            if freq <= 0:
                raise ValueError
        except ValueError:
            errors["czestotliwosc_miesiace"] = (
                "Częstotliwość musi być dodatnią liczbą całkowitą."
            )

        # --- Jeśli brak błędów, zapisujemy przegląd ---
        if not errors:
            property_name = normalize_property_name(form_data["nieruchomosc"])
            next_date, status = compute_next_and_status(
                form_data["ostatnia_data"], freq
            )

            inspection = {
                "nazwa": form_data["nazwa"],
                "nieruchomosc": property_name,
                "ostatnia_data": form_data["ostatnia_data"],
                "czestotliwosc_miesiace": freq,
                "kolejna_data": next_date,
                "status": status,
                "opis": clean_empty_notes(form_data["opis"]),
                "firma": form_data["firma"],
                "telefon": form_data["telefon"],
                "email": form_data["email"],
            }

            inspections.append(inspection)
            save_inspections(inspections)
            return redirect(url_for("index"))

    # --- Przy GET lub przy błędach walidacji: przygotowanie podpowiedzi ---

    # podpowiedzi do nazwy
    used_names = get_unique_names(inspections)

    # podpowiedzi do nieruchomości
    used_properties = get_unique_properties(inspections)

    # podpowiedzi do firmy
    used_companies = sorted({ins["firma"] for ins in inspections if ins.get("firma")})

    # mapa firma -> kontakt (tel, email) do JS
    company_contacts = {}
    for ins in inspections:
        firma = ins.get("firma")
        if not firma:
            continue
        company_contacts[firma] = {
            "telefon": ins.get("telefon", ""),
            "email": ins.get("email", ""),
        }

    return render_template(
        "form.html",
        mode="add",
        errors=errors,
        form=form_data,
        used_names=used_names,
        used_properties=used_properties,
        used_companies=used_companies,
        company_contacts=company_contacts,
        idx=None,
    )


@app.route("/edit/<int:idx>", methods=["GET", "POST"])
def edit(idx: int):
    inspections = load_inspections()

    # walidacja indexu
    if idx < 0 or idx >= len(inspections):
        return "Nie znaleziono przeglądu.", 404

    ins = inspections[idx]

    errors = {}
    form_data = {
        "nazwa": ins.get("nazwa", ""),
        "nieruchomosc": ins.get("nieruchomosc", ""),
        "ostatnia_data": ins.get("ostatnia_data", ""),
        "czestotliwosc_miesiace": str(ins.get("czestotliwosc_miesiace", "")),
        "opis": ins.get("opis", ""),
        "firma": ins.get("firma", ""),
        "telefon": ins.get("telefon", ""),
        "email": ins.get("email", ""),
    }

    if request.method == "POST":
        form_data["nazwa"] = request.form.get("nazwa", "").strip()
        form_data["nieruchomosc"] = request.form.get("nieruchomosc", "").strip()
        form_data["ostatnia_data"] = request.form.get("ostatnia_data", "").strip()
        form_data["czestotliwosc_miesiace"] = request.form.get(
            "czestotliwosc_miesiace", ""
        ).strip()
        form_data["opis"] = request.form.get("opis", "").strip()
        form_data["firma"] = request.form.get("firma", "").strip()
        form_data["telefon"] = request.form.get("telefon", "").strip()
        form_data["email"] = request.form.get("email", "").strip()

        if not form_data["nazwa"]:
            errors["nazwa"] = "Nazwa jest wymagana."
        if not form_data["nieruchomosc"]:
            errors["nieruchomosc"] = "Nieruchomość jest wymagana."

        try:
            parse_date(form_data["ostatnia_data"])
        except ValueError as e:
            errors["ostatnia_data"] = str(e)

        try:
            freq = int(form_data["czestotliwosc_miesiace"])
            if freq <= 0:
                raise ValueError
        except ValueError:
            errors["czestotliwosc_miesiace"] = (
                "Częstotliwość musi być dodatnią liczbą całkowitą."
            )

        if not errors:
            property_name = normalize_property_name(form_data["nieruchomosc"])
            next_date, status = compute_next_and_status(
                form_data["ostatnia_data"], freq
            )

            ins["nazwa"] = form_data["nazwa"]
            ins["nieruchomosc"] = property_name
            ins["ostatnia_data"] = form_data["ostatnia_data"]
            ins["czestotliwosc_miesiace"] = freq
            ins["kolejna_data"] = next_date
            ins["status"] = status
            ins["opis"] = clean_empty_notes(form_data["opis"])
            ins["firma"] = form_data["firma"]
            ins["telefon"] = form_data["telefon"]
            ins["email"] = form_data["email"]

            save_inspections(inspections)
            return redirect(url_for("index"))

    # podpowiedzi (takie same jak przy dodawaniu)
    used_names = get_unique_names(inspections)
    used_properties = get_unique_properties(inspections)
    used_companies = sorted({ins["firma"] for ins in inspections if ins.get("firma")})

    company_contacts = {}
    for item in inspections:
        firma = item.get("firma")
        if not firma:
            continue
        company_contacts[firma] = {
            "telefon": item.get("telefon", ""),
            "email": item.get("email", ""),
        }

    return render_template(
        "form.html",
        mode="edit",
        errors=errors,
        form=form_data,
        used_names=used_names,
        used_properties=used_properties,
        used_companies=used_companies,
        company_contacts=company_contacts,
        idx=idx,
    )


@app.route("/delete/<int:idx>", methods=["POST"])
def delete(idx: int):
    inspections = load_inspections()

    if idx < 0 or idx >= len(inspections):
        return "Nie znaleziono przeglądu.", 404

    del inspections[idx]
    save_inspections(inspections)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
