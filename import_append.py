import json
from datetime import date

from app import (
    SessionLocal,
    Inspection,
    ensure_property_ids,
    ensure_property_record,
    get_or_create_property_id,
    parse_date,
)


def load_data(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    data = load_data("przeglady.json")
    ensure_property_ids(data)

    db = SessionLocal()

    for item in data:
        prop = (item.get("nieruchomosc") or "").strip()
        name = (item.get("nazwa") or "").strip()
        if not prop or not name:
            continue

        last_raw = (item.get("ostatnia_data") or "").strip()
        try:
            last_dt = parse_date(last_raw) if last_raw else None
        except ValueError:
            continue

        existing = (
            db.query(Inspection)
            .filter(
                Inspection.nieruchomosc == prop,
                Inspection.nazwa == name,
                Inspection.ostatnia_data == last_dt,
            )
            .first()
        )
        if existing:
            continue

        pid = item.get("property_id") or get_or_create_property_id(db, prop)
        seg = item.get("segment") or ""
        ensure_property_record(db, prop, property_id=pid, segment=seg)

        freq = item.get("czestotliwosc_miesiace") or 1
        try:
            freq = int(freq)
            if freq <= 0:
                freq = 1
        except Exception:
            freq = 1

        next_raw = (item.get("kolejna_data") or "").strip()
        try:
            next_dt = date.fromisoformat(next_raw) if next_raw else None
        except Exception:
            next_dt = None
        if not last_dt:
            last_dt = date.today()
        if not next_dt:
            from app import add_months

            next_dt = add_months(last_dt, freq)

        new_ins = Inspection(
            nazwa=name,
            nieruchomosc=prop,
            property_id=pid,
            ostatnia_data=last_dt,
            czestotliwosc_miesiace=freq,
            kolejna_data=next_dt,
            status=item.get("status") or "Aktualne",
            opis=item.get("opis") or "Brak uwag",
            firma=item.get("firma") or "",
            telefon=item.get("telefon") or "",
            email=item.get("email") or "",
            segment=seg,
            owner=item.get("owner") or "admin",
        )
        db.add(new_ins)

    db.commit()
    db.close()
    print("Import zakończony.")


if __name__ == "__main__":
    main()
