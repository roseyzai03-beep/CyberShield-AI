"""
database.py
SQLite persistence layer for scan results.
"""

import sqlite3
import json
import os
from datetime import datetime, timezone

# Absolute path so the DB is always found, whatever the working directory is.
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cybersecurity.db')


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            threats TEXT NOT NULL,
            details TEXT NOT NULL,
            source_type TEXT NOT NULL DEFAULT 'File',
            created_at TEXT NOT NULL
        )
    ''')
    # Migrate older databases that were created before source_type existed.
    existing = {row['name'] for row in cur.execute('PRAGMA table_info(scans)')}
    if 'source_type' not in existing:
        cur.execute("ALTER TABLE scans ADD COLUMN source_type TEXT NOT NULL DEFAULT 'File'")
    conn.commit()
    conn.close()


def save_scan(filename, risk_score, risk_level, threats, details, source_type='File'):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO scans (filename, risk_score, risk_level, threats, details, source_type, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        filename,
        int(risk_score),
        risk_level,
        json.dumps(threats),
        json.dumps(details),
        source_type,
        datetime.now(timezone.utc).isoformat(timespec='seconds'),
    ))
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id


def _row_to_dict(row):
    keys = row.keys()
    return {
        'id': row['id'],
        'filename': row['filename'],
        'risk_score': row['risk_score'],
        'risk_level': row['risk_level'],
        'threats': json.loads(row['threats']),
        'details': json.loads(row['details']),
        'source_type': row['source_type'] if 'source_type' in keys else 'File',
        'created_at': row['created_at'],
    }


def get_all_scans(limit=50):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM scans ORDER BY id DESC LIMIT ?', (limit,))
    rows = cur.fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def get_scan_by_id(scan_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    row = cur.fetchone()
    conn.close()
    return _row_to_dict(row) if row else None
