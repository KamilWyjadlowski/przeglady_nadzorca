import json
from datetime import date
from typing import Optional


def get_input(prompt: str) -> str:
    """Input z obsługą komendy 'menu'."""
    text = input(prompt).strip()
    if text.lower() == "menu":
        raise KeyboardInterrupt  # użyjemy tego jako sygnału "wróć do menu"
    return text


DATA_FILE = "przeglady.json"


def parse_date(user_input: str) -> date:
    """
    Przyjmuje datę w formacie:
    - RRRR-MM-DD  (np. 2025-08-12)
    - albo DD.MM.RRRR (np. 12.08.2025)
    Zwraca obiekt date albo rzuca ValueError.
    """
    s = user_input.strip()

    # format z kropkami: DD.MM.RRRR
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
                # jak się nie da sparsować, lecimy niżej do ISO
                pass

    # standardowy format ISO: RRRR-MM-DD
    try:
        return date.fromisoformat(s)
    except ValueError:
        raise ValueError(
            f"Nieprawidłowy format daty: '{user_input}'. "
            "Użyj RRRR-MM-DD (np. 2025-08-12) albo DD.MM.RRRR (np. 12.08.2025)."
        )


def normalize_property_name(raw: str) -> str:
    """
    Normalizuje zapis nieruchomości tak, żeby każde słowo
    zaczynało się z dużej litery, a reszta była mała.
    Np. 'bydgoszcz magazynowa 13' -> 'Bydgoszcz Magazynowa 13'.
    """
    parts = raw.strip().split()
    return " ".join(p.capitalize() for p in parts)


def add_months(d: date, months: int) -> date:
    """Dodaje X miesięcy do daty (np. 12 = rok)."""
    month = d.month - 1 + months
    year = d.year + month // 12
    month = month % 12 + 1

    # ile dni ma dany miesiąc
    days_in_month = [
        31,
        29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28,
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    ][month - 1]

    day = min(d.day, days_in_month)
    return date(year, month, day)


def load_inspections() -> list:
    """Wczytuje listę przeglądów z pliku JSON (albo pustą listę)."""
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return []


def list_by_status(status_filter: str) -> None:
    """Wypisuje przeglądy o podanym statusie."""
    print(f"\n--- Przeglądy ze statusem: {status_filter} ---")
    inspections = load_inspections()

    filtered = [ins for ins in inspections if ins["status"] == status_filter]

    if not filtered:
        print(f"Brak przeglądów ze statusem {status_filter}.\n")
        return

    for i, ins in enumerate(filtered, start=1):
        nier = ins.get("nieruchomosc", "(brak przypisanej nieruchomości)")
        print(f"{i}. {ins['nazwa']}")
        print(f"   Nieruchomość: {nier}")
        print(f"   Ostatnia data: {ins['ostatnia_data']}")
        print(f"   Częstotliwość: {ins['czestotliwosc_miesiace']} mies.")
        print(f"   Kolejna data: {ins['kolejna_data']}")
        print(f"   Status: {ins['status']}")
        if ins.get("opis"):
            print(f"   Opis: {ins['opis']}")
        print()
    print()


from typing import Optional

from typing import Optional  # upewnij się, że ten import jest na górze pliku

def choose_inspection() -> Optional[int]:
    """Pokazuje listę i pozwala wybrać przegląd numerem. Zwraca index lub None."""
    inspections = load_inspections()

    if not inspections:
        print("\nBrak przeglądów.\n")
        return None

    print("\n--- Wybierz przegląd ---")
    for i, ins in enumerate(inspections, start=1):
        nier = ins.get("nieruchomosc", "brak nieruchomości")
        print(f"{i}. {ins['nazwa']} [{nier}] (następny: {ins['kolejna_data']}, status: {ins['status']})")

    choice = input("Podaj numer (albo Enter aby anulować, wpisz 'menu' aby wrócić): ").strip()

    if choice == "":
        # anulowanie wyboru, po prostu wyjście z akcji
        return None

    if choice.lower() == "menu":
        print("\n↩️   Powrót do menu głównego.\n")
        return None

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(inspections):
            return idx
        else:
            print("Niepoprawny numer.\n")
            return None
    except ValueError:
        print("To nie jest liczba.\n")
        return None


def edit_inspection() -> None:
    idx = choose_inspection()
    if idx is None:
        return

    inspections = load_inspections()
    ins = inspections[idx]

    print("\n--- Edycja przeglądu ---")
    print("(Pozostaw puste i naciśnij Enter, aby nie zmieniać)")

    current_property = ins.get("nieruchomosc", "")
    new_name = input(f"Nazwa [{ins['nazwa']}]: ").strip()
    new_property = input(f"Nieruchomość [{current_property}]: ").strip()
    new_last_date = input(f"Ostatnia data [{ins['ostatnia_data']}]: ").strip()
    new_freq = input(f"Częstotliwość mies. [{ins['czestotliwosc_miesiace']}]: ").strip()
    new_opis = input(f"Opis [{ins.get('opis','')}]: ").strip()

    if new_name:
        ins["nazwa"] = new_name

    if new_property:
        ins["nieruchomosc"] = normalize_property_name(new_property)

    if new_last_date:
        try:
            # sprawdzamy poprawność
            parse_date(new_last_date)
            ins["ostatnia_data"] = new_last_date
        except ValueError as e:
            print(f"Błąd daty: {e}\n")
            return

    if new_freq:
        try:
            ins["czestotliwosc_miesiace"] = int(new_freq)
        except ValueError:
            print("Częstotliwość musi być liczbą.\n")
            return

    if new_opis:
        ins["opis"] = new_opis

    # przeliczamy ponownie kolejną datę i status
    next_date, status = compute_next_and_status(
        ins["ostatnia_data"], ins["czestotliwosc_miesiace"]
    )
    ins["kolejna_data"] = next_date
    ins["status"] = status

    save_inspections(inspections)

    print("\n✅ Zmieniono pomyślnie.")
    print(f"   Nieruchomość: {ins.get('nieruchomosc', '(brak)')}")
    print(f"   Nowa kolejna data: {next_date}")
    print(f"   Status: {status}\n")


def delete_inspection() -> None:
    idx = choose_inspection()
    if idx is None:
        return

    inspections = load_inspections()
    ins = inspections[idx]

    confirm = input(f"Czy na pewno usunąć '{ins['nazwa']}'? (t/n): ").lower().strip()

    if confirm == "t":
        del inspections[idx]
        save_inspections(inspections)
        print("\n🗑️ Usunięto.\n")
    else:
        print("\nAnulowano.\n")


def save_inspections(inspections: list) -> None:
    """Zapisuje listę przeglądów do pliku JSON."""
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(inspections, f, ensure_ascii=False, indent=2)


def compute_next_and_status(last_date_str: str, freq_months: int) -> tuple[str, str]:
    """Liczy kolejną datę i status (Zaległy / Nadchodzi / Aktualne)."""
    last = parse_date(last_date_str)
    next_dt = add_months(last, freq_months)
    today = date.today()

    if next_dt < today:
        status = "Zaległy"
    elif (next_dt - today).days <= 30:
        status = "Nadchodzi"
    else:
        status = "Aktualne"

    return next_dt.isoformat(), status


def add_inspection() -> None:
    """Dodaje nowy przegląd na podstawie danych od użytkownika."""
    print("\n--- Dodawanie przeglądu ---")
       
     # --- Podpowiedzi nazw ---
    inspections = load_inspections()
    used_names = sorted({ins["nazwa"] for ins in inspections})

    if used_names:
        print("\nDostępne nazwy (podpowiedzi):")
        for n in used_names:
            print(f" - {n}")
    else:
        print("\nBrak podpowiedzi – to pierwszy przegląd.")

    name = input("Nazwa przeglądu: ").strip()
    last_date_str = input(
        "Data ostatniego przeglądu (DD.MM.RRRR): "
    ).strip()
    freq_str = input("Częstotliwość w miesiącach (np. 12): ").strip()

    try:
        freq = int(freq_str)
    except ValueError:
        print("Częstotliwość musi być liczbą całkowitą. Przerywam dodawanie.\n")
        return

    try:
        next_date, status = compute_next_and_status(last_date_str, freq)
    except ValueError as e:
        print(f"{e}\n")
        return

    opis = input("Opis (opcjonalnie, możesz zostawić puste): ").strip()

    inspection = {
        "nazwa": name,
        "ostatnia_data": last_date_str,
        "czestotliwosc_miesiace": freq,
        "kolejna_data": next_date,
        "status": status,
        "opis": opis,
    }

    inspections = load_inspections()
    inspections.append(inspection)
    save_inspections(inspections)

    print("\n✅ Przegląd zapisany.")
    print(f"   Kolejna data: {next_date}")
    print(f"   Status: {status}\n")


def add_inspection() -> None:
    """Dodaje nowy przegląd na podstawie danych od użytkownika."""
    print("\n--- Dodawanie przeglądu ---")

    inspections = load_inspections()
    used_names = sorted({ins["nazwa"] for ins in inspections})

    if used_names:
        print("\nDostępne nazwy (podpowiedzi):")
        for n in used_names:
            print(f" - {n}")
    else:
        print("\nBrak podpowiedzi – to pierwszy przegląd.")

    name = input("Nazwa przeglądu: ").strip()
    property_raw = input("Nieruchomość (np. Miasto, ul. Przykładowa 10): ").strip()
    property_name = normalize_property_name(property_raw)


    # --- pętla o poprawną datę ---
    while True:
        last_date_str = input(
            "Data ostatniego przeglądu (RRRR-MM-DD lub DD.MM.RRRR): "
        ).strip()
        try:
            # tylko sprawdzamy, czy da się sparsować
            parse_date(last_date_str)
            break
        except ValueError as e:
            print(f"{e}")
            print("Spróbuj jeszcze raz.\n")

    # --- pętla o poprawną częstotliwość ---
    while True:
        freq_str = input("Częstotliwość w miesiącach (np. 12): ").strip()
        try:
            freq = int(freq_str)
            if freq <= 0:
                raise ValueError
            break
        except ValueError:
            print("Częstotliwość musi być dodatnią liczbą całkowitą. Spróbuj jeszcze raz.\n")

    # skoro data i częstotliwość są już poprawne, tu się nie wywali
    next_date, status = compute_next_and_status(last_date_str, freq)

    opis = input("Opis (opcjonalnie, możesz zostawić puste): ").strip()

    inspection = {
        "nazwa": name,
        "nieruchomosc": property_name,
        "ostatnia_data": last_date_str,
        "czestotliwosc_miesiace": freq,
        "kolejna_data": next_date,
        "status": status,
        "opis": opis,
    }

    inspections.append(inspection)
    save_inspections(inspections)

    print("\n✅ Przegląd zapisany.")
    print(f"   Nieruchomość: {property_name or '(brak)'}")
    print(f"   Kolejna data: {next_date}")
    print(f"   Status: {status}\n")


def list_inspections() -> None:
    """Wypisuje wszystkie przeglądy."""
    print("\n--- Lista przeglądów ---")
    inspections = load_inspections()

    if not inspections:
        print("Brak zapisanych przeglądów.\n")
        return

    for i, ins in enumerate(inspections, start=1):
        nier = ins.get("nieruchomosc", "(brak przypisanej nieruchomości)")
        print(f"{i}. {ins['nazwa']}")
        print(f"   Nieruchomość: {nier}")
        print(f"   Ostatnia data: {ins['ostatnia_data']}")
        print(f"   Częstotliwość (miesiące): {ins['czestotliwosc_miesiace']}")
        print(f"   Kolejna data: {ins['kolejna_data']}")
        print(f"   Status: {ins['status']}")
        if ins.get("opis"):
            print(f"   Opis: {ins['opis']}")
        print()
    print()


def main_menu() -> None:
    """Proste menu główne w terminalu."""
    while True:
        print("1. Dodaj przegląd")
        print("2. Pokaż wszystkie przeglądy")
        print("3. Pokaż zaległe")
        print("4. Pokaż nadchodzące")
        print("5. Pokaż aktualne")
        print("6. Edytuj przegląd")
        print("7. Usuń przegląd")
        print("0. Wyjście")


        choice = input("Wybierz opcję: ").strip()

        if choice == "1":
            add_inspection()
        elif choice == "2":
            list_inspections()
        elif choice == "3":
            list_by_status("Zaległy")
        elif choice == "4":
            list_by_status("Nadchodzi")
        elif choice == "5":
            list_by_status("Aktualne")
        elif choice == "6":
            edit_inspection()
        elif choice == "7":
            delete_inspection()
        elif choice == "0":
            print("Do zobaczenia!")
            break
        else:
            print("Nieprawidłowy wybór, spróbuj jeszcze raz.\n")


if __name__ == "__main__":
    while True:
        try:
            main_menu()
        except KeyboardInterrupt:
            print("\n↩️   Powrót do menu głównego.\n")
            continue
