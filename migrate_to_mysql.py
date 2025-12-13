"""
Migracja danych z plików JSON do MySQL (Cloud SQL lub inny).

Wymagane zmienne środowiskowe:
- DB_HOST
- DB_PORT (domyślnie 3306)
- DB_USER
- DB_PASSWORD
- DB_NAME

Użycie:
  python migrate_to_mysql.py

Skrypt:
- tworzy tabele (jeśli nie istnieją),
- wczytuje users.json, przeglady.json, property_access.json, audit.log,
- uzupełnia brakujące property_id w przeglądach (P0001 itd.),
- wstawia dane do MySQL.
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path

import pymysql

DB_HOST = os.getenv("DB_HOST")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")

BASE_DIR = Path(__file__).parent


def ensure_conn():
    missing = [k for k, v in {"DB_HOST": DB_HOST, "DB_USER": DB_USER, "DB_PASSWORD": DB_PASSWORD, "DB_NAME": DB_NAME}.items() if not v]
    if missing:
        raise SystemExit(f"Brak zmiennych: {', '.join(missing)}")
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )


DDL = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'user'
    ) CHARACTER SET utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS inspections (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nazwa VARCHAR(255) NOT NULL,
        nieruchomosc VARCHAR(255) NOT NULL,
        property_id VARCHAR(32),
        ostatnia_data DATE NOT NULL,
        czestotliwosc_miesiace INT NOT NULL,
        kolejna_data DATE NOT NULL,
        status VARCHAR(32) NOT NULL,
        opis TEXT,
        firma VARCHAR(255),
        telefon VARCHAR(64),
        email VARCHAR(255),
        segment VARCHAR(32),
        owner VARCHAR(100) NOT NULL
    ) CHARACTER SET utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS property_access (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nieruchomosc VARCHAR(255) NOT NULL,
        username VARCHAR(100) NOT NULL
    ) CHARACTER SET utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS audit (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        ts DATETIME NOT NULL,
        action VARCHAR(64) NOT NULL,
        user VARCHAR(100),
        details JSON
    ) CHARACTER SET utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS properties (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) UNIQUE NOT NULL,
        property_id VARCHAR(32),
        segment VARCHAR(32)
    ) CHARACTER SET utf8mb4;
    """,
]


def ensure_property_ids(items):
    mapping = {}
    max_num = 0
    pat = re.compile(r"^P(\d+)$")

    for ins in items:
        pid = ins.get("property_id", "")
        if pid:
            mapping.setdefault(ins.get("nieruchomosc"), pid)
            m = pat.match(pid)
            if m:
                max_num = max(max_num, int(m.group(1)))

    changed = False
    for ins in items:
        if not ins.get("property_id"):
            max_num += 1
            pid = f"P{max_num:04d}"
            ins["property_id"] = pid
            mapping.setdefault(ins.get("nieruchomosc"), pid)
            changed = True
    return changed


def load_json(path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8") or json.dumps(default))


def migrate():
    conn = ensure_conn()
    with conn.cursor() as cur:
        for stmt in DDL:
            cur.execute(stmt)

    users = load_json(BASE_DIR / "users.json", [])
    inspections = load_json(BASE_DIR / "przeglady.json", [])
    property_access = load_json(BASE_DIR / "property_access.json", {})
    audit_lines = []
    audit_path = BASE_DIR / "audit.log"
    if audit_path.exists():
        for line in audit_path.read_text(encoding="utf-8").splitlines():
            try:
                audit_lines.append(json.loads(line))
            except Exception:
                pass

    ensure_property_ids(inspections)

    with conn.cursor() as cur:
        # Czyścimy w kolejności dziecko -> rodzic, bez kolizji FK
        cur.execute("DELETE FROM inspection_occurrences")
        cur.execute("DELETE FROM inspections")
        cur.execute("DELETE FROM property_access")
        cur.execute("DELETE FROM audit")

        # Resetujemy AUTO_INCREMENT
        cur.execute("ALTER TABLE inspection_occurrences AUTO_INCREMENT = 1")
        cur.execute("ALTER TABLE inspections AUTO_INCREMENT = 1")
        cur.execute("ALTER TABLE property_access AUTO_INCREMENT = 1")
        cur.execute("ALTER TABLE audit AUTO_INCREMENT = 1")

        if inspections:
            cur.executemany(
                """INSERT INTO inspections
                (nazwa, nieruchomosc, property_id, ostatnia_data, czestotliwosc_miesiace,
                 kolejna_data, status, opis, firma, telefon, email, segment, owner)
                 VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                [
                    (
                        ins.get("nazwa", ""),
                        ins.get("nieruchomosc", ""),
                        ins.get("property_id", ""),
                        ins.get("ostatnia_data", None),
                        ins.get("czestotliwosc_miesiace", 0),
                        ins.get("kolejna_data", None),
                        ins.get("status", ""),
                        ins.get("opis", ""),
                        ins.get("firma", ""),
                        ins.get("telefon", ""),
                        ins.get("email", ""),
                        ins.get("segment", ""),
                        ins.get("owner", ""),
                    )
                    for ins in inspections
                ],
            )

        if property_access:
            rows = []
            for prop, users_list in property_access.items():
                for u in users_list:
                    rows.append((prop, u))
            if rows:
                cur.executemany(
                    "INSERT INTO property_access (nieruchomosc, username) VALUES (%s, %s)",
                    rows,
                )

        if audit_lines:
            cur.executemany(
                "INSERT INTO audit (ts, action, user, details) VALUES (%s,%s,%s,%s)",
                [
                    (
                        a.get("ts").replace("Z", "").replace("T", " "),
                        a.get("action", ""),
                        a.get("user", ""),
                        json.dumps(a.get("details", {}), ensure_ascii=False),
                    )
                    for a in audit_lines
                    if a.get("ts")
                ],
            )

    conn.close()
    print("Migracja zakończona.")


if __name__ == "__main__":
    migrate()
