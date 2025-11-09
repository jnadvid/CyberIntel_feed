#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cyber-News Enhanced - Professional Cybersecurity Feed Aggregator
Optimizado para análisis de inteligencia de amenazas y monitorización de vulnerabilidades
"""
import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse

import feedparser
import opml
from dateutil import parser as dateparser
from flask import Flask, abort, jsonify, redirect, render_template_string, request, url_for, flash, send_file
from jinja2 import DictLoader
import csv
import io

# --- Begin runtime tweaks (Windows/Flask/Dateutil) ---
try:
    import warnings
    from dateutil.parser._parser import UnknownTimezoneWarning
    warnings.filterwarnings("ignore", category=UnknownTimezoneWarning)
except Exception:
    pass

# --- Begin network hardening ---
try:
    import socket
    socket.setdefaulttimeout(10)
except Exception:
    pass

# Monkeypatch requests to enforce default timeouts & UA if missing
try:
    import requests
    _orig_request = requests.Session.request
    def _patched_request(self, method, url, **kwargs):
        if "timeout" not in kwargs or kwargs["timeout"] is None:
            kwargs["timeout"] = (5, 10)
        headers = kwargs.get("headers") or {}
        if "User-Agent" not in headers:
            headers["User-Agent"] = "CyberNewsFetcher/1.0 (+https://local)"
        kwargs["headers"] = headers
        return _orig_request(self, method, url, **kwargs)
    if not getattr(requests.Session.request, "__name__", "") == "_patched_request":
        requests.Session.request = _patched_request
except ImportError:
    pass
except Exception:
    pass

APP_NAME = "CyberIntel Feed Aggregator"
VERSION = "2.0"
BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.environ.get("CYBERNEWS_DB", os.path.join(BASE_DIR, "cyberintel.db"))
DEFAULT_OPML = os.path.join(BASE_DIR, "feeds.opml")

FEED_CATEGORIES = {
    'threat-intel': ['threat', 'intel', 'apt', 'malware', 'ransomware', 'botnet'],
    'vulnerabilities': ['vuln', 'cve', 'exploit', 'zero-day', '0day', 'patch'],
    'ot-ics': ['ics', 'scada', 'plc', 'ot', 'industrial', 'critical infrastructure'],
    'cloud-security': ['cloud', 'aws', 'azure', 'gcp', 'kubernetes', 'docker'],
    'incident-response': ['dfir', 'forensic', 'incident', 'breach', 'response'],
    'red-team': ['pentest', 'red team', 'offensive', 'exploit', 'hack'],
    'blue-team': ['defense', 'soc', 'siem', 'detection', 'hunting'],
    'compliance': ['compliance', 'nist', 'iso', 'gdpr', 'nis2', 'regulation'],
    'research': ['research', 'analysis', 'reverse', 'bug bounty'],
    'news': ['news', 'update', 'announce', 'release']
}

CRITICAL_KEYWORDS = {
    'ot-threats': ['modbus', 'dnp3', 'iec-104', 'opcua', 'profinet', 'ethernet/ip',
                   'triton', 'industroyer', 'stuxnet', 'blackenergy', 'havex'],
    'critical-vulns': ['rce', 'remote code execution', 'authentication bypass',
                       'privilege escalation', 'zero-day', 'critical vulnerability'],
    'apt-groups': ['apt28', 'apt29', 'lazarus', 'carbanak', 'fin7', 'cozy bear',
                   'fancy bear', 'equation group', 'darkhydrus'],
    'ransomware': ['lockbit', 'blackcat', 'alphv', 'conti', 'revil', 'darkside',
                   'ryuk', 'maze', 'egregor', 'sodinokibi'],
    'supply-chain': ['supply chain', 'solarwinds', 'kaseya', 'codecov', 'dependency confusion']
}

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

@app.route("/health")
def health():
    return jsonify({"status": "ok", "app": APP_NAME, "version": VERSION}), 200

@app.route("/favicon.ico")
def favicon():
    return ("", 204)

# ---------------- Base de Datos ----------------
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA cache_size=10000;")
    return conn

def init_db():
    with closing(get_conn()) as conn, conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS feeds(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                xmlUrl TEXT UNIQUE NOT NULL,
                type TEXT,
                siteUrl TEXT,
                category TEXT,
                tags TEXT,
                reliability_score REAL DEFAULT 0.5,
                last_updated TEXT,
                last_checked TEXT,
                error_count INTEGER DEFAULT 0,
                active BOOLEAN DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now'))
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS entries(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                feed_id INTEGER NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
                title TEXT,
                link TEXT,
                author TEXT,
                published TEXT,
                summary TEXT,
                content TEXT,
                guid TEXT UNIQUE NOT NULL,
                threat_level INTEGER DEFAULT 0,
                keywords TEXT,
                category TEXT,
                read BOOLEAN DEFAULT 0,
                starred BOOLEAN DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS threat_analysis(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id INTEGER REFERENCES entries(id) ON DELETE CASCADE,
                threat_type TEXT,
                severity TEXT,
                iocs TEXT,
                mitre_tactics TEXT,
                affected_systems TEXT,
                recommendations TEXT,
                analyzed_at TEXT DEFAULT (datetime('now'))
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS statistics(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT,
                metric_type TEXT,
                metric_name TEXT,
                metric_value REAL,
                details TEXT
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_feed_published ON entries(feed_id, published DESC);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_published ON entries(published DESC);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_threat ON entries(threat_level DESC);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_category ON entries(category);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_feeds_category ON feeds(category);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_feeds_active ON feeds(active);")
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5(
                title, summary, content, link, guid, keywords,
                content='entries', content_rowid='id',
                tokenize='porter unicode61'
            );
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS entries_ai AFTER INSERT ON entries BEGIN
              INSERT INTO entries_fts(rowid, title, summary, content, link, guid, keywords)
              VALUES (new.id, new.title, new.summary, new.content, new.link, new.guid, new.keywords);
            END;
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS entries_ad AFTER DELETE ON entries BEGIN
              DELETE FROM entries_fts WHERE rowid = old.id;
            END;
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS entries_au AFTER UPDATE ON entries BEGIN
              UPDATE entries_fts SET
                title = new.title,
                summary = new.summary,
                content = new.content,
                link = new.link,
                guid = new.guid,
                keywords = new.keywords
              WHERE rowid = new.id;
            END;
        """)

# ---------------- Funciones de Análisis ----------------
def analyze_threat_level(text: str, title: str = "", link: str = "") -> int:
    if not text:
        return 0
    text_lower = f"{title} {text} {link}".lower()
    threat_score = 0
    for category, keywords in CRITICAL_KEYWORDS.items():
        for keyword in keywords:
            if keyword.lower() in text_lower:
                if category in ['ot-threats', 'apt-groups', 'ransomware']:
                    threat_score += 2
                elif category in ['critical-vulns', 'supply-chain']:
                    threat_score += 1.5
                else:
                    threat_score += 1
    if 'critical' in text_lower or 'emergency' in text_lower:
        threat_score += 1
    if 'zero-day' in text_lower or '0day' in text_lower:
        threat_score += 2
    if 'actively exploited' in text_lower:
        threat_score += 2
    if re.search(r'cve-\d{4}-\d+', text_lower):
        threat_score += 0.5
    return min(int(threat_score), 5)

def categorize_entry(text: str, title: str = "") -> str:
    combined = f"{title} {text}".lower()
    scores = defaultdict(int)
    for category, keywords in FEED_CATEGORIES.items():
        for keyword in keywords:
            if keyword in combined:
                scores[category] += 1
    if scores:
        return max(scores, key=scores.get)
    return 'news'

def extract_keywords(text: str, title: str = "") -> str:
    combined = f"{title} {text}".lower()
    keywords = set()
    cves = re.findall(r'cve-\d{4}-\d+', combined, re.IGNORECASE)
    keywords.update(cves)
    for category in ['apt-groups', 'ransomware', 'ot-threats']:
        for keyword in CRITICAL_KEYWORDS.get(category, []):
            if keyword.lower() in combined:
                keywords.add(keyword.lower())
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', combined)
    keywords.update(ips[:5])
    hashes = re.findall(r'\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b', combined)
    keywords.update(hashes[:3])
    return ', '.join(sorted(keywords)[:20])

# ---------------- Importación de Feeds ----------------
def import_feed(conn, feed_row: dict, verbose: bool = False) -> Tuple[int, int, int]:
    url = feed_row["xmlUrl"]
    feed_id = feed_row["id"]
    try:
        parsed = feedparser.parse(url)
        if parsed.bozo and not parsed.entries:
            conn.execute("UPDATE feeds SET error_count = error_count + 1 WHERE id = ?", (feed_id,))
            return 0, 0, 1
        inserted = 0
        skipped = 0
        errors = 0
        for entry in parsed.entries:
            try:
                guid = entry.get("id") or entry.get("link") or hashlib.md5(
                    f"{entry.get('title', '')}_{entry.get('published', '')}".encode()
                ).hexdigest()
                existing = conn.execute("SELECT id FROM entries WHERE guid = ?", (guid,)).fetchone()
                if existing:
                    skipped += 1
                    continue
                published = None
                if hasattr(entry, "published_parsed") and entry.published_parsed:
                    published = datetime(*entry.published_parsed[:6]).isoformat()
                elif hasattr(entry, "updated_parsed") and entry.updated_parsed:
                    published = datetime(*entry.updated_parsed[:6]).isoformat()
                else:
                    try:
                        if entry.get("published"):
                            published = dateparser.parse(entry.published).isoformat()
                        elif entry.get("updated"):
                            published = dateparser.parse(entry.updated).isoformat()
                    except:
                        published = datetime.now().isoformat()
                summary = entry.get("summary", "")
                content = ""
                if hasattr(entry, "content") and entry.content:
                    content = entry.content[0].get("value", "")
                threat_level = analyze_threat_level(f"{summary} {content}", entry.get("title", ""), entry.get("link", ""))
                category = categorize_entry(f"{summary} {content}", entry.get("title", ""))
                keywords = extract_keywords(f"{summary} {content}", entry.get("title", ""))
                conn.execute("""
                    INSERT INTO entries(
                        feed_id, title, link, author, published, summary,
                        content, guid, threat_level, keywords, category
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    feed_id,
                    entry.get("title", "Sin título"),
                    entry.get("link", ""),
                    entry.get("author", ""),
                    published,
                    summary,
                    content,
                    guid,
                    threat_level,
                    keywords,
                    category
                ))
                inserted += 1
            except Exception as e:
                errors += 1
                if verbose:
                    print(f"Error procesando entrada: {e}")
        conn.execute("""
            UPDATE feeds
            SET last_updated = datetime('now'),
                last_checked = datetime('now'),
                error_count = 0
            WHERE id = ?
        """, (feed_id,))
        return inserted, skipped, errors
    except Exception as e:
        if verbose:
            print(f"Error accediendo al feed {url}: {e}")
        conn.execute("UPDATE feeds SET error_count = error_count + 1 WHERE id = ?", (feed_id,))
        return 0, 0, 1

def import_from_opml(opml_path: str, analyze: bool = True) -> Tuple[int, int, int]:
    try:
        with open(opml_path, 'r', encoding='utf-8') as f:
            outline = opml.parse(f)
    except Exception as e:
        print(f"Error leyendo OPML: {e}")
        return 0, 0, 1
    total_inserted = 0
    total_feeds = 0
    total_errors = 0
    with closing(get_conn()) as conn, conn:
        for item in outline:
            if hasattr(item, 'xmlUrl'):
                try:
                    existing = conn.execute("SELECT id FROM feeds WHERE xmlUrl = ?", (item.xmlUrl,)).fetchone()
                    if not existing:
                        category = categorize_entry(getattr(item, 'text', '') + ' ' + getattr(item, 'title', ''))
                        cur = conn.execute("""
                            INSERT INTO feeds(title, xmlUrl, type, siteUrl, category)
                            VALUES (?, ?, ?, ?, ?)
                        """, (
                            getattr(item, 'title', getattr(item, 'text', 'Sin título')),
                            item.xmlUrl,
                            getattr(item, 'type', 'rss'),
                            getattr(item, 'htmlUrl', ''),
                            category
                        ))
                        feed_id = cur.lastrowid
                        feed_row = {"id": feed_id, "xmlUrl": item.xmlUrl}
                    else:
                        feed_row = conn.execute("SELECT * FROM feeds WHERE id = ?", (existing['id'],)).fetchone()
                    if analyze:
                        ins, skip, err = import_feed(conn, feed_row)
                        total_inserted += ins
                        total_errors += err
                    total_feeds += 1
                except Exception as e:
                    print(f"Error procesando feed {item.xmlUrl}: {e}")
                    total_errors += 1
    return total_inserted, total_feeds, total_errors

def discover_feeds_from_html(url: str) -> Optional[str]:
    try:
        import requests, re
        resp = requests.get(url, timeout=(5,10), headers={'User-Agent':'CyberIntel/2.0'})
        if resp.status_code >= 400:
            return None
        m = re.search(r"<link[^>]+rel=['\"]alternate['\"][^>]+type=['\"](application/(?:rss|atom)\+xml|application/json)['\"][^>]+href=['\"]([^'\"]+)['\"]", resp.text, re.I)
        if m:
            from urllib.parse import urljoin
            return urljoin(url, m.group(2))
    except Exception:
        return None
    return None

def normalize_special_feed(url: str) -> Optional[str]:
    import re
    yt = re.search(r'(?:youtube\.com/(?:channel/|@)|youtu\.be/)([A-Za-z0-9_\-@]+)', url)
    if yt:
        cid = yt.group(1)
        if cid.startswith('@'):
            return None
        return f'https://www.youtube.com/feeds/videos.xml?channel_id={cid}'
    gh = re.search(r'github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)', url)
    if gh:
        owner, repo = gh.groups()
        return f'https://github.com/{owner}/{repo}/releases.atom'
    return None

# ---------------- Plantillas HTML ----------------
TEMPLATES = {
    'base.html': '''<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{% block title %}{{ APP_NAME }}{% endblock %}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #000000;
            --bg-secondary: #0a0a0a;
            --bg-tertiary: #1a1a1a;
            --bg-elevated: #252525;
            --border-primary: #333333;
            --border-secondary: #4a4a4a;
            --text-primary: #ffffff;
            --text-secondary: #e0e0e0;
            --text-tertiary: #b0b0b0;
            --text-muted: #808080;
            --accent-blue: #00d4ff;
            --accent-blue-hover: #0099cc;
            --accent-blue-light: #66e0ff;
            --success: #00ff88;
            --warning: #ffaa00;
            --danger: #ff4444;
            --critical: #ff0000;
            --shadow-sm: 0 4px 8px rgba(0, 0, 0, 0.3);
            --shadow-md: 0 8px 16px rgba(0, 0, 0, 0.4);
            --shadow-lg: 0 16px 32px rgba(0, 0, 0, 0.5);
            --radius-sm: 8px;
            --radius-md: 12px;
            --radius-lg: 16px;
            --gradient-primary: linear-gradient(135deg, #00d4ff 0%, #0099cc 50%, #0066aa 100%);
            --gradient-secondary: linear-gradient(135deg, #1a1a1a 0%, #252525 100%);
            --gradient-accent: linear-gradient(135deg, #00ff88 0%, #00cc66 100%);
        }
        
        * { 
            margin: 0; 
            padding: 0; 
            box-sizing: border-box; 
        }
        
        html { 
            font-size: 16px;
            scroll-behavior: smooth;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: var(--bg-primary);
            color: var(--text-secondary);
            line-height: 1.7;
            font-size: 1rem;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        .container { 
            max-width: 1800px; 
            margin: 0 auto; 
            padding: 0 40px;
        }
        
        /* HEADER */
        header { 
            background: var(--gradient-secondary); 
            padding: 40px 0; 
            border-bottom: 3px solid var(--border-primary);
            box-shadow: var(--shadow-lg);
            margin-bottom: 50px;
            position: sticky;
            top: 0;
            z-index: 100;
            backdrop-filter: blur(20px);
            border-image: var(--gradient-primary) 1;
        }
        
        header h1 { 
            color: var(--text-primary);
            font-size: 2.75rem;
            font-weight: 900;
            letter-spacing: -1.5px;
            margin-bottom: 8px;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-shadow: 0 0 20px rgba(0, 212, 255, 0.3);
        }
        
        header p {
            color: var(--text-tertiary);
            font-size: 1.1rem;
            text-transform: uppercase;
            letter-spacing: 3px;
            font-weight: 700;
            background: linear-gradient(90deg, var(--accent-blue-light), var(--success));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        /* NAVIGATION */
        nav { 
            margin: 0 0 50px 0;
            background: var(--bg-secondary);
            border-radius: var(--radius-lg);
            border: 2px solid var(--border-primary);
            display: flex;
            flex-wrap: wrap;
            gap: 0;
            box-shadow: var(--shadow-lg);
            overflow: hidden;
            backdrop-filter: blur(10px);
        }
        
        nav a { 
            color: var(--text-tertiary);
            text-decoration: none;
            padding: 20px 32px;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            font-size: 1rem;
            font-weight: 700;
            flex: 1;
            text-align: center;
            border-bottom: 4px solid transparent;
            position: relative;
            letter-spacing: 0.5px;
        }
        
        nav a::before {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            width: 0;
            height: 4px;
            background: var(--gradient-primary);
            transition: width 0.4s ease;
            border-radius: 0 0 4px 4px;
        }
        
        nav a:hover { 
            background: var(--bg-elevated);
            color: var(--text-primary);
            transform: translateY(-2px) scale(1.02);
            box-shadow: 0 4px 12px rgba(0, 212, 255, 0.2);
        }
        
        nav a:hover::before {
            width: 100%;
        }
        
        /* CARDS */
        .card { 
            background: var(--gradient-secondary); 
            border: 2px solid var(--border-primary);
            border-radius: var(--radius-lg);
            padding: 40px;
            margin-bottom: 40px;
            box-shadow: var(--shadow-md);
            transition: all 0.4s ease;
            position: relative;
            overflow: hidden;
        }
        
        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 1px;
            background: var(--gradient-primary);
            opacity: 0.5;
        }
        
        .card:hover {
            box-shadow: var(--shadow-lg);
            border-color: var(--accent-blue);
            transform: translateY(-5px);
        }
        
        .card h2 { 
            font-size: 2.25rem;
            font-weight: 800;
            margin-bottom: 30px;
            color: var(--text-primary);
            padding-bottom: 20px;
            border-bottom: 3px solid var(--border-primary);
            letter-spacing: -0.8px;
            background: linear-gradient(90deg, var(--text-primary), var(--accent-blue-light));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .card h3 { 
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 25px;
            color: var(--text-secondary);
            letter-spacing: -0.4px;
            position: relative;
        }
        
        .card h3::after {
            content: '';
            position: absolute;
            bottom: -5px;
            left: 0;
            width: 50px;
            height: 2px;
            background: var(--gradient-accent);
            border-radius: 1px;
        }
        
        /* STATS GRID */
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); 
            gap: 30px; 
            margin-bottom: 50px;
        }
        
        .stat-card { 
            background: var(--gradient-secondary);
            padding: 40px;
            border-radius: var(--radius-lg);
            border: 2px solid var(--border-primary);
            text-align: center;
            box-shadow: var(--shadow-md);
            transition: all 0.4s ease;
            position: relative;
            overflow: hidden;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 6px;
            background: var(--gradient-primary);
        }
        
        .stat-card:hover {
            transform: translateY(-8px) rotateX(5deg);
            box-shadow: var(--shadow-lg);
            border-color: var(--accent-blue);
        }
        
        .stat-number { 
            font-size: 3.5rem;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 900;
            line-height: 1;
            margin-bottom: 15px;
            font-family: 'JetBrains Mono', monospace;
            text-shadow: 0 0 20px rgba(0, 212, 255, 0.5);
        }
        
        .stat-label { 
            color: var(--text-tertiary);
            margin-top: 10px;
            font-size: 1rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            position: relative;
        }
        
        /* TABLES */
        table { 
            width: 100%; 
            border-collapse: separate;
            border-spacing: 0;
            background: var(--bg-secondary);
            font-size: 0.95rem;
            border-radius: var(--radius-md);
            overflow: hidden;
            box-shadow: var(--shadow-md);
        }
        
        thead { 
            background: var(--gradient-secondary);
        }
        
        th { 
            padding: 20px 24px; 
            text-align: left; 
            color: var(--text-tertiary);
            font-weight: 800;
            border-bottom: 3px solid var(--border-primary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1.5px;
        }
        
        td { 
            padding: 18px 24px; 
            border-bottom: 1px solid var(--border-primary);
            color: var(--text-secondary);
            font-size: 0.95rem;
            transition: all 0.3s ease;
        }
        
        tbody tr {
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
        }
        
        tbody tr::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            width: 4px;
            height: 100%;
            background: transparent;
            transition: background 0.3s ease;
        }
        
        tbody tr:hover { 
            background: var(--bg-elevated);
            transform: scale(1.02);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
        
        tbody tr:hover::before {
            background: var(--gradient-primary);
        }
        
        tbody tr:last-child td {
            border-bottom: none;
        }
        
        /* THREAT LEVELS */
        .threat-0 { 
            color: var(--text-muted); 
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
        }
        .threat-1 { 
            color: var(--success); 
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
            text-shadow: 0 0 8px rgba(0, 255, 136, 0.4);
        }
        .threat-2 { 
            color: var(--warning); 
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
            text-shadow: 0 0 8px rgba(255, 170, 0, 0.4);
        }
        .threat-3 { 
            color: #ff6600; 
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
            text-shadow: 0 0 10px rgba(255, 102, 0, 0.5);
        }
        .threat-4 { 
            color: var(--danger); 
            font-weight: 900;
            font-family: 'JetBrains Mono', monospace;
            text-shadow: 0 0 12px rgba(255, 68, 68, 0.6);
            animation: glow 1.5s infinite alternate;
        }
        .threat-5 { 
            color: var(--critical); 
            font-weight: 900;
            font-family: 'JetBrains Mono', monospace;
            animation: pulse 1s infinite, glow 0.5s infinite alternate;
            text-shadow: 0 0 20px rgba(255, 0, 0, 0.8);
        }
        
        @keyframes glow {
            from { text-shadow: 0 0 5px currentColor; }
            to { text-shadow: 0 0 20px currentColor; }
        }
        
        @keyframes pulse { 
            0%, 100% { opacity: 1; transform: scale(1); } 
            50% { opacity: 0.9; transform: scale(1.1); } 
        }
        
        /* FORM ELEMENTS */
        input[type="text"],
        input[type="url"],
        input[type="file"],
        select,
        textarea { 
            width: 100%; 
            padding: 16px 20px; 
            background: var(--bg-elevated); 
            border: 2px solid var(--border-primary);
            color: var(--text-primary);
            border-radius: var(--radius-md);
            margin-bottom: 20px;
            font-size: 1rem;
            font-family: inherit;
            transition: all 0.4s ease;
            font-weight: 600;
            box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.2);
        }
        
        input[type="text"]:focus,
        input[type="url"]:focus,
        input[type="file"]:focus,
        select:focus,
        textarea:focus { 
            outline: none;
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 4px rgba(0, 212, 255, 0.2), inset 0 2px 4px rgba(0, 0, 0, 0.1);
            background: var(--bg-secondary);
            transform: scale(1.02);
        }
        
        input[type="checkbox"] {
            width: 24px;
            height: 24px;
            cursor: pointer;
            accent-color: var(--accent-blue);
            margin-right: 12px;
            transform: scale(1.2);
        }
        
        /* BUTTONS */
        button, .btn { 
            background: var(--gradient-primary);
            color: #ffffff;
            border: none; 
            padding: 16px 28px; 
            border-radius: var(--radius-md); 
            cursor: pointer; 
            font-weight: 800;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            text-decoration: none; 
            display: inline-block;
            font-size: 1rem;
            letter-spacing: 0.5px;
            box-shadow: var(--shadow-md);
            text-transform: uppercase;
            position: relative;
            overflow: hidden;
        }
        
        button::before, .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s;
        }
        
        button:hover, .btn:hover { 
            transform: translateY(-3px) scale(1.05);
            box-shadow: var(--shadow-lg);
        }
        
        button:hover::before, .btn:hover::before {
            left: 100%;
        }
        
        button:active, .btn:active { 
            transform: translateY(-1px);
            box-shadow: var(--shadow-sm);
        }
        
        .btn-danger { 
            background: linear-gradient(135deg, var(--danger) 0%, var(--critical) 100%);
        }
        
        .btn-danger:hover { 
            box-shadow: 0 8px 20px rgba(255, 68, 68, 0.4);
        }
        
        /* ALERTS */
        .alert { 
            padding: 20px 28px;
            border-radius: var(--radius-md);
            margin-bottom: 30px;
            font-size: 1rem;
            border-left: 5px solid;
            font-weight: 600;
            box-shadow: var(--shadow-sm);
            animation: slideIn 0.5s ease-out;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        
        .alert-success { 
            background: rgba(0, 255, 136, 0.1);
            border-left-color: var(--success);
            color: var(--success);
        }
        
        .alert-error { 
            background: rgba(255, 68, 68, 0.1);
            border-left-color: var(--danger);
            color: var(--danger);
        }
        
        /* SEARCH BOX */
        .search-box { 
            margin-bottom: 40px;
        }
        
        .search-box form {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            align-items: flex-end;
            background: var(--bg-elevated);
            padding: 20px;
            border-radius: var(--radius-lg);
            border: 1px solid var(--border-primary);
        }
        
        .search-box input, 
        .search-box select { 
            margin-bottom: 0;
            flex: 1;
            min-width: 280px;
        }
        
        .search-box button {
            white-space: nowrap;
        }
        
        /* CATEGORY BADGES */
        .category-badge { 
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 800;
            color: #ffffff;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .category-badge::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, rgba(255,255,255,0.1), transparent);
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        
        .category-badge:hover::before {
            opacity: 1;
        }
        
        .category-threat-intel { background: linear-gradient(135deg, #8b0000 0%, #a52a2a 100%); }
        .category-vulnerabilities { background: linear-gradient(135deg, #b8860b 0%, #daa520 100%); }
        .category-ot-ics { background: linear-gradient(135deg, #006400 0%, #228b22 100%); }
        .category-cloud-security { background: linear-gradient(135deg, #00008b 0%, #4169e1 100%); }
        .category-incident-response { background: linear-gradient(135deg, #8b0000 0%, #a52a2a 100%); }
        .category-red-team { background: linear-gradient(135deg, #800000 0%, #b22222 100%); }
        .category-blue-team { background: linear-gradient(135deg, #0000cd 0%, #4169e1 100%); }
        .category-compliance { background: linear-gradient(135deg, #4b0082 0%, #9370db 100%); }
        .category-research { background: linear-gradient(135deg, #008b8b 0%, #20b2aa 100%); }
        .category-news { background: linear-gradient(135deg, #696969 0%, #a9a9a9 100%); }
        
        /* FOOTER */
        footer { 
            text-align: center;
            padding: 50px 30px;
            color: var(--text-muted);
            margin-top: 80px;
            border-top: 3px solid var(--border-primary);
            font-size: 1rem;
            font-weight: 600;
            background: var(--gradient-secondary);
            box-shadow: 0 -4px 12px rgba(0, 0, 0, 0.3);
        }
        
        /* LINKS */
        a { 
            color: var(--accent-blue-light); 
            text-decoration: none;
            transition: all 0.3s ease;
            position: relative;
        }
        
        a::after {
            content: '';
            position: absolute;
            bottom: -2px;
            left: 0;
            width: 0;
            height: 2px;
            background: var(--gradient-primary);
            transition: width 0.3s ease;
        }
        
        a:hover { 
            color: var(--accent-blue);
            text-decoration: none;
        }
        
        a:hover::after {
            width: 100%;
        }
        
        /* SCROLLBAR */
        ::-webkit-scrollbar {
            width: 14px;
            height: 14px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--bg-primary);
            border-radius: 7px;
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--gradient-primary);
            border-radius: 7px;
            border: 2px solid var(--bg-primary);
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: var(--accent-blue-hover);
        }
        
        /* RESPONSIVE */
        @media (max-width: 768px) {
            html { font-size: 15px; }
            .container { padding: 0 24px; }
            header h1 { font-size: 2.25rem; }
            nav a { padding: 16px 20px; }
            .card { padding: 28px; }
            .stat-number { font-size: 2.75rem; }
            .stats-grid { grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        }
        
        @media (max-width: 480px) {
            .search-box form { flex-direction: column; align-items: stretch; }
            .search-box input, .search-box select { min-width: auto; }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>{{ APP_NAME }}</h1>
            <p>Inteligencia de Amenazas en Tiempo Real</p>
        </div>
    </header>
    <div class="container">
        <nav>
            <a href="{{ url_for('index') }}">Dashboard</a>
            <a href="{{ url_for('entries') }}">Entradas</a>
            <a href="{{ url_for('feeds_manage') }}">Feeds</a>
            <a href="{{ url_for('threat_analysis') }}">Análisis</a>
            <a href="{{ url_for('search') }}">Búsqueda</a>
            <a href="{{ url_for('statistics') }}">Estadísticas</a>
            <a href=\"{{ url_for('licencica') }}\">Licencia</a>
        </nav>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </div>
    <footer>
        <p>{{ APP_NAME }} v{{ VERSION }} • Última actualización: {{ now }} • 
Autor: <a href='https://www.israelnadal.com' target='_blank' rel='noopener'>José Israel Nadal Vidal</a> • 
Licencia: <a href='https://creativecommons.org/licenses/by-nc-nd/4.0/' target='_blank' rel='noopener'>CC BY-NC-ND 4.0</a> • 
Email: <a href='mailto:jose.nadal@gmail.com'>jose.nadal@gmail.com</a></p>
<div style='margin-top:10px;'>
    <a href='https://creativecommons.org/licenses/by-nc-nd/4.0/' target='_blank' rel='noopener'>
        <img src='https://licensebuttons.net/l/by-nc-nd/4.0/88x31.png' alt='CC BY-NC-ND 4.0' style='border:0;'></a>
</div>
</footer>
</body>
</html>''',

    'index.html': '''{% extends "base.html" %}
{% block title %}Dashboard - {{ APP_NAME }}{% endblock %}
{% block content %}
<div class="card">
    <h2>Panel de Control de Inteligencia</h2>
</div>
<div class="stats-grid">
    <div class="stat-card"><div class="stat-number">{{ total_feeds }}</div><div class="stat-label">Feeds Activos</div></div>
    <div class="stat-card"><div class="stat-number">{{ total_entries }}</div><div class="stat-label">Total Entradas</div></div>
    <div class="stat-card"><div class="stat-number">{{ entries_24h }}</div><div class="stat-label">Últimas 24h</div></div>
    <div class="stat-card"><div class="stat-number">{{ critical_threats }}</div><div class="stat-label">Amenazas Críticas</div></div>
</div>
<div class="card">
    <h3>Amenazas Críticas Recientes</h3>
    <table>
        <thead><tr><th>Título</th><th>Feed</th><th>Nivel</th><th>Categoría</th><th>Fecha</th></tr></thead>
        <tbody>
            {% for entry in recent_critical %}
            <tr>
                <td><a href="{{ entry.link }}" target="_blank">{{ entry.title[:80] }}</a></td>
                <td>{{ entry.feed_title }}</td>
                <td class="threat-{{ entry.threat_level }}">{{ entry.threat_level }}</td>
                <td><span class="category-badge category-{{ entry.category }}">{{ entry.category }}</span></td>
                <td>{{ entry.published[:10] if entry.published else "N/A" }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
<div class="card">
    <h3>Distribución por Categorías</h3>
    <table>
        <thead><tr><th>Categoría</th><th>Entradas</th><th>Porcentaje</th></tr></thead>
        <tbody>
            {% for cat in category_stats %}
            <tr>
                <td><span class="category-badge category-{{ cat.category }}">{{ cat.category }}</span></td>
                <td>{{ cat.count }}</td>
                <td>{{ "%.1f"|format(cat.percentage) }}%</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
{% endblock %}''',

    'feeds.html': '''{% extends "base.html" %}
{% block title %}Gestión de Feeds - {{ APP_NAME }}{% endblock %}
{% block content %}
<div class="card">
    <h2>Gestión de Feeds RSS</h2>
</div>
<div class="card">
    <h3>Agregar Feed</h3>
    <form method="post" action="{{ url_for('add_feed') }}">
        <input type="url" name="url" placeholder="URL del feed RSS" required>
        <input type="text" name="title" placeholder="Título (opcional)">
        <select name="category">
            <option value="">-- Categoría Automática --</option>
            {% for cat in categories %}
            <option value="{{ cat }}">{{ cat }}</option>
            {% endfor %}
        </select>
        <button type="submit">Agregar Feed</button>
    </form>
</div>
<div class="card">
    <h3>Importar OPML</h3>
    <form method="post" action="{{ url_for('import_opml') }}" enctype="multipart/form-data">
        <input type="file" name="opml_file" accept=".opml,.xml" required>
        <button type="submit">Importar</button>
    </form>
    <div style="margin-top: 20px; display: flex; gap: 12px;">
        <a href="{{ url_for('export_opml') }}" class="btn">Exportar OPML</a>
        <a href="{{ url_for('export_csv', time='7d') }}" class="btn">Exportar CSV</a>
    </div>
</div>
<div class="card">
    <h3>Feeds Activos ({{ feeds|length }})</h3>
    <div style='margin-bottom:20px; display:flex; gap:12px;'>
      <form method='post' action='{{ url_for("refresh_all_feeds") }}' style='display:inline'>
        <button class='btn' type='submit'>Actualizar todos</button>
      </form>
    </div>
    <form method='post' action='{{ url_for("refresh_selected_feeds") }}'>
      <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr>
            <th style="width: 50px;"><input type='checkbox' id='check_all' title='Seleccionar todos' style='width: 20px; height: 20px; cursor: pointer;' onclick="for(const cb of document.querySelectorAll('.feed-check')) cb.checked=this.checked;"></th>
            <th>ID</th><th>Título</th><th>Categoría</th><th>Entradas</th><th>Última Actualización</th><th>Última Entrada</th><th>Errores</th><th>Acciones</th>
          </tr>
        </thead>
        <tbody>
          {% for feed in feeds %}
          <tr>
            <td style="width: 50px; text-align: center;"><input type='checkbox' class='feed-check' name='feed_id' value='{{ feed.id }}' style='width: 20px; height: 20px; cursor: pointer;'></td>
            <td>{{ feed.id }}</td>
            <td><a href="{{ feed.siteUrl or feed.xmlUrl }}" target="_blank">{{ feed.title or "Sin título" }}</a></td>
            <td><span class="category-badge category-{{ feed.category }}">{{ feed.category or "N/A" }}</span></td>
            <td>{{ feed.entry_count }}</td>
            <td>{{ feed.last_updated[:16] if feed.last_updated else "Nunca" }}</td>
            <td style="color: var(--text-tertiary);">{% if feed.preview_title %}{{ feed.preview_title[:60] }}...{% else %}<span style="color: var(--text-muted);">Sin entradas</span>{% endif %}</td>
            <td>{{ feed.error_count }}</td>
            <td>
              <form method="post" action="{{ url_for('refresh_feed', feed_id=feed.id) }}" style="display: inline;"><button type="submit">Actualizar</button></form>
              {% if feed.active %}
              <form method="post" action="{{ url_for('toggle_feed', feed_id=feed.id) }}" style="display: inline;"><button type="submit" class="btn-danger">Pausar</button></form>
              {% else %}
              <form method="post" action="{{ url_for('toggle_feed', feed_id=feed.id) }}" style="display: inline;"><button type="submit">Reanudar</button></form>
              {% endif %}
              <form method="post" action="{{ url_for('delete_feed', feed_id=feed.id) }}" style="display: inline;" onsubmit="return confirm('¿Eliminar este feed y todas sus entradas?');"><button type="submit" class="btn-danger">Eliminar</button></form>
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      </div>
      <div style='margin-top:20px;'>
        <button class='btn' type='submit'>Actualizar seleccionados</button>
      </div>
    </form>
</div>
{% endblock %}''',

    'entries.html': '''{% extends "base.html" %}
{% block title %}Entradas - {{ APP_NAME }}{% endblock %}
{% block content %}
<div class="card">
    <h2>Entradas de Feeds</h2>
</div>
<div class="search-box">
    <form method="get">
        <input type="text" name="q" placeholder="Buscar en entradas..." value="{{ query }}">
        <select name="category">
            <option value="">Todas las categorías</option>
            {% for cat in categories %}
            <option value="{{ cat }}" {% if cat == selected_category %}selected{% endif %}>{{ cat }}</option>
            {% endfor %}
        </select>
        <select name="threat">
            <option value="">Todos los niveles</option>
            {% for i in range(6) %}
            <option value="{{ i }}" {% if threat_level == i %}selected{% endif %}>Nivel {{ i }}</option>
            {% endfor %}
        </select>
        <button type="submit">Buscar</button>
    </form>
</div>
<div class="card">
    <table>
        <thead><tr><th>Título</th><th>Feed</th><th>Amenaza</th><th>Categoría</th><th>Keywords</th><th>Publicado</th></tr></thead>
        <tbody>
            {% for entry in entries %}
            <tr>
                <td><a href="{{ entry.link }}" target="_blank">{{ entry.title[:100] }}</a></td>
                <td>{{ entry.feed_title }}</td>
                <td class="threat-{{ entry.threat_level }}">{{ entry.threat_level }}</td>
                <td><span class="category-badge category-{{ entry.category }}">{{ entry.category }}</span></td>
                <td style="font-size: 0.85em; color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">{{ entry.keywords[:50] if entry.keywords else "" }}</td>
                <td>{{ entry.published[:16] if entry.published else "N/A" }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
{% endblock %}'''
}

app.jinja_loader = DictLoader(TEMPLATES)

# ---------------- Rutas Web ----------------
@app.context_processor
def inject_globals():
    return {'APP_NAME': APP_NAME, 'VERSION': VERSION, 'now': datetime.now().strftime('%Y-%m-%d %H:%M')}

@app.route("/")
def index():
    with closing(get_conn()) as conn:
        total_feeds = conn.execute("SELECT COUNT(*) FROM feeds WHERE active = 1").fetchone()[0]
        total_entries = conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        entries_24h = conn.execute("SELECT COUNT(*) FROM entries WHERE published >= datetime('now', '-1 day')").fetchone()[0]
        critical_threats = conn.execute("SELECT COUNT(*) FROM entries WHERE threat_level >= 4").fetchone()[0]
        recent_critical = conn.execute("""
            SELECT e.*, f.title as feed_title
            FROM entries e JOIN feeds f ON e.feed_id = f.id
            WHERE e.threat_level >= 3
            ORDER BY e.published DESC
            LIMIT 10
        """).fetchall()
        category_stats = conn.execute("""
            SELECT category, COUNT(*) as count
            FROM entries GROUP BY category ORDER BY count DESC
        """).fetchall()
        total = sum(cat['count'] for cat in category_stats) or 1
        category_stats = [{'category': cat['category'], 'count': cat['count'], 'percentage': (cat['count']/total)*100} for cat in category_stats]
    return render_template_string(
        TEMPLATES['index.html'],
        total_feeds=total_feeds, total_entries=total_entries,
        entries_24h=entries_24h, critical_threats=critical_threats,
        recent_critical=recent_critical, category_stats=category_stats
    )

@app.route("/entries")
def entries():
    page = int(request.args.get("page", 1))
    per_page = 50
    query = request.args.get("q", "")
    selected_category = request.args.get("category", "")
    threat_level = request.args.get("threat", "")
    with closing(get_conn()) as conn:
        where_clauses, params = [], []
        if query:
            where_clauses.append("(e.title LIKE ? OR e.summary LIKE ? OR e.keywords LIKE ?)")
            params.extend([f"%{query}%"]*3)
        if selected_category:
            where_clauses.append("e.category = ?"); params.append(selected_category)
        if threat_level:
            where_clauses.append("e.threat_level = ?"); params.append(int(threat_level))
        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
        total = conn.execute(f"SELECT COUNT(*) FROM entries e WHERE {where_sql}", params).fetchone()[0]
        entries_list = conn.execute(f"""
            SELECT e.*, f.title as feed_title
            FROM entries e JOIN feeds f ON e.feed_id = f.id
            WHERE {where_sql}
            ORDER BY e.published DESC
            LIMIT ? OFFSET ?
        """, params + [per_page, (page-1)*per_page]).fetchall()
        categories = [row[0] for row in conn.execute("SELECT DISTINCT category FROM entries ORDER BY category").fetchall()]
    total_pages = (total + per_page - 1) // per_page if per_page else 1
    return render_template_string(
        TEMPLATES['entries.html'],
        entries=entries_list, page=page, total_pages=total_pages,
        prev_page=page-1 if page > 1 else None, next_page=page+1 if page < total_pages else None,
        query=query, categories=categories, selected_category=selected_category, threat_level=threat_level
    )

@app.route("/feeds")
def feeds_manage():
    with closing(get_conn()) as conn:
        feeds = conn.execute("""
            SELECT f.*, COUNT(e.id) as entry_count,
                   (SELECT e2.title FROM entries e2 WHERE e2.feed_id=f.id ORDER BY e2.published DESC LIMIT 1) as preview_title,
                   (SELECT e2.published FROM entries e2 WHERE e2.feed_id=f.id ORDER BY e2.published DESC LIMIT 1) as preview_date
            FROM feeds f
            LEFT JOIN entries e ON f.id = e.feed_id
            GROUP BY f.id
            ORDER BY f.title
        """).fetchall()
        categories = list(FEED_CATEGORIES.keys())
    return render_template_string(TEMPLATES['feeds.html'], feeds=feeds, categories=categories)

@app.route("/feeds/add", methods=["POST"])
def add_feed():
    url = request.form.get("url")
    title = request.form.get("title", "")
    category = request.form.get("category", "")
    if not url:
        flash("URL requerida", "error")
        return redirect(url_for("feeds_manage"))
    auto_url = normalize_special_feed(url) or url
    if not auto_url.lower().endswith((".xml",".rss",".atom",".json")):
        discovered = discover_feeds_from_html(auto_url)
        if discovered:
            auto_url = discovered
    with closing(get_conn()) as conn, conn:
        try:
            existing = conn.execute("SELECT id FROM feeds WHERE xmlUrl = ?", (auto_url,)).fetchone()
            if existing:
                flash("Este feed ya existe", "error")
                return redirect(url_for("feeds_manage"))
            if not category:
                category = categorize_entry(title)
            cur = conn.execute("INSERT INTO feeds(title, xmlUrl, category) VALUES (?,?,?)", (title or "Nuevo Feed", auto_url, category))
            feed_id = cur.lastrowid
            feed_row = {"id": feed_id, "xmlUrl": auto_url}
            ins, skip, err = import_feed(conn, feed_row)
            flash(f"Feed agregado: {ins} entradas importadas", "success")
        except Exception as e:
            flash(f"Error: {e}", "error")
    return redirect(url_for("feeds_manage"))

@app.route("/feeds/<int:feed_id>/refresh", methods=["POST"])
def refresh_feed(feed_id):
    with closing(get_conn()) as conn, conn:
        feed = conn.execute("SELECT * FROM feeds WHERE id = ?", (feed_id,)).fetchone()
        if not feed:
            abort(404)
        ins, skip, err = import_feed(conn, feed)
        flash(f"Feed actualizado: {ins} nuevas, {skip} duplicadas, {err} errores", "success")
    return redirect(url_for("feeds_manage"))

@app.route("/feeds/<int:feed_id>/toggle", methods=["POST"])
def toggle_feed(feed_id):
    with closing(get_conn()) as conn, conn:
        conn.execute("UPDATE feeds SET active = NOT active WHERE id = ?", (feed_id,))
        flash("Estado del feed actualizado", "success")
    return redirect(url_for("feeds_manage"))

@app.route("/feeds/<int:feed_id>/delete", methods=["POST"])
def delete_feed(feed_id):
    with closing(get_conn()) as conn, conn:
        conn.execute("DELETE FROM feeds WHERE id = ?", (feed_id,))
        flash("Feed eliminado", "success")
    return redirect(url_for("feeds_manage"))

@app.route("/feeds/refresh_all", methods=["POST"])
def refresh_all_feeds():
    updated = 0; new_items = 0; errors = 0
    with closing(get_conn()) as conn, conn:
        feeds = conn.execute("SELECT * FROM feeds WHERE active=1").fetchall()
        for f in feeds:
            ins, skip, err = import_feed(conn, f)
            new_items += ins; errors += err; updated += 1
    flash(f"Actualizados {updated} feeds. Nuevas entradas: {new_items}. Errores: {errors}", "success")
    return redirect(url_for("feeds_manage"))

@app.route("/feeds/refresh_selected", methods=["POST"])
def refresh_selected_feeds():
    ids = request.form.getlist("feed_id")
    if not ids:
        flash("Selecciona al menos un feed.", "error")
        return redirect(url_for("feeds_manage"))
    placeholders = ",".join("?" for _ in ids)
    updated = 0; new_items = 0; errors = 0
    with closing(get_conn()) as conn, conn:
        rows = conn.execute(f"SELECT * FROM feeds WHERE id IN ({placeholders})", ids).fetchall()
        for f in rows:
            ins, skip, err = import_feed(conn, f)
            new_items += ins; errors += err; updated += 1
    flash(f"Actualizados {updated} feeds seleccionados. Nuevas entradas: {new_items}. Errores: {errors}", "success")
    return redirect(url_for("feeds_manage"))

@app.route("/import", methods=["POST"])
def import_opml():
    file = request.files.get("opml_file")
    if not file or not file.filename.lower().endswith((".opml", ".xml")):
        flash("Por favor sube un archivo OPML o XML válido.", "error")
        return redirect(url_for("feeds_manage"))
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".opml")
    file.save(tmp.name)
    try:
        inserted, feeds, errors = import_from_opml(tmp.name, analyze=False)
        flash(f"Importación completada: {feeds} feeds procesados, {inserted} entradas nuevas.", "success")
    except Exception as e:
        flash(f"Error importando OPML: {e}", "error")
    finally:
        try: os.remove(tmp.name)
        except OSError: pass
    return redirect(url_for("feeds_manage"))

@app.route("/export/opml")
def export_opml():
    with closing(get_conn()) as conn:
        feeds = conn.execute("SELECT * FROM feeds WHERE active = 1 ORDER BY title").fetchall()
    opml_content = '''<?xml version="1.0" encoding="UTF-8"?>
<opml version="2.0">
<head>
    <title>CyberIntel Feed Export</title>
    <dateCreated>{}</dateCreated>
</head>
<body>
'''.format(datetime.now().isoformat())
    for feed in feeds:
        opml_content += f'''    <outline text="{feed['title'] or ''}" title="{feed['title'] or ''}" type="rss" xmlUrl="{feed['xmlUrl']}" htmlUrl="{feed['siteUrl'] or ''}" category="{feed['category'] or ''}"/>\n'''
    opml_content += '''</body>
</opml>'''
    output = io.BytesIO()
    output.write(opml_content.encode('utf-8'))
    output.seek(0)
    return send_file(output, mimetype='text/xml', as_attachment=True,
                     download_name=f'cyberintel_feeds_{datetime.now().strftime("%Y%m%d")}.opml')

@app.route("/export/csv")
def export_csv():
    time_filter = request.args.get("time", "7d")
    with closing(get_conn()) as conn:
        query = """
            SELECT e.title, e.link, e.published, e.threat_level, e.keywords, e.category, f.title as feed_title
            FROM entries e JOIN feeds f ON e.feed_id = f.id
            WHERE e.published >= date('now', ?)
            ORDER BY e.published DESC
        """
        time_map = {"1d":"-1 day","7d":"-7 days","30d":"-30 days","all":"-100 years"}
        entries = conn.execute(query, (time_map.get(time_filter, "-7 days"),)).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Título', 'URL', 'Fecha', 'Nivel Amenaza', 'Keywords', 'Categoría', 'Feed'])
    for entry in entries:
        writer.writerow([entry['title'], entry['link'], entry['published'], entry['threat_level'],
                         entry['keywords'], entry['category'], entry['feed_title']])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode('utf-8')), mimetype='text/csv',
                     as_attachment=True, download_name=f'cyberintel_export_{datetime.now().strftime("%Y%m%d")}.csv')

@app.route("/threat-analysis")
def threat_analysis():
    with closing(get_conn()) as conn:
        items = conn.execute("""
            SELECT e.*, f.title as feed_title
            FROM entries e JOIN feeds f ON e.feed_id=f.id
            WHERE e.threat_level >= 4
            ORDER BY e.published DESC
            LIMIT 100
        """).fetchall()
    html = ["<h2>Análisis de Amenazas</h2>", "<div class='card'>",
            """<div style='margin-bottom:15px; display:flex; gap:12px;'><form method='post' action='{{ url_for("refresh_selected_feeds") }}' style='display:inline'><button class='btn' type='submit'>Actualizar seleccionados</button></form><form method='post' action='{{ url_for("refresh_all_feeds") }}' style='display:inline'><button class='btn' type='submit'>Actualizar todos</button></form></div><table><thead><tr><th>Título</th><th>Feed</th><th>Nivel</th><th>Categoría</th><th>Fecha</th></tr></thead><tbody>"""]
    for it in items:
        html.append(f"<tr><td><a target='_blank' href='{it['link']}'>{(it['title'] or '')[:100]}</a></td>"
                    f"<td>{it['feed_title']}</td>"
                    f"<td class='threat-{it['threat_level']}'>{it['threat_level']}</td>"
                    f"<td><span class='category-badge category-{it['category']}'>{it['category']}</span></td>"
                    f"<td>{(it['published'] or '')[:16]}</td></tr>")
    html.append("</tbody></table></div>")
    return render_template_string(TEMPLATES['base.html'].replace('{% block content %}{% endblock %}',
                                                                 '{% block content %}'+"".join(html)+'{% endblock %}'))

@app.route("/search")
def search():
    q = request.args.get("q","")
    category = request.args.get("category","")
    min_level = request.args.get("min_level","")
    with closing(get_conn()) as conn:
        clauses=["1=1"]; params=[]
        if q:
            clauses.append("(e.title LIKE ? OR e.summary LIKE ? OR e.keywords LIKE ?)")
            params += [f"%{q}%", f"%{q}%", f"%{q}%"]
        if category:
            clauses.append("e.category = ?"); params.append(category)
        if min_level:
            clauses.append("e.threat_level >= ?"); params.append(int(min_level))
        where_sql = " AND ".join(clauses)
        results = conn.execute(f"""
            SELECT e.*, f.title as feed_title
            FROM entries e JOIN feeds f ON e.feed_id=f.id
            WHERE {where_sql}
            ORDER BY e.published DESC
            LIMIT 300
        """, params).fetchall()
        categories = [row[0] for row in conn.execute("SELECT DISTINCT category FROM entries ORDER BY category").fetchall()]
    table = ["<h2>Búsqueda</h2>", "<div class='card'>",
             "<form method='get'><input type='text' name='q' value='{}' placeholder='palabras clave/cve'>".format(q),
             "<div style='display:flex;gap:12px;margin-top:12px'>",
             "<select name='category' style='width:auto'><option value=''>Todas</option>",
             *[f"<option value='{c}' {'selected' if c==category else ''}>{c}</option>" for c in categories],
             "</select>",
             "<select name='min_level' style='width:auto'><option value=''>Nivel ≥</option>",
             *[f"<option value='{i}' {'selected' if str(i)==str(min_level) else ''}>{i}</option>" for i in range(6)],
             "</select><button class='btn' type='submit'>Buscar</button></div></form></div>",
             """<div class='card'><div style='margin-bottom:15px; display:flex; gap:12px;'><form method='post' action='{{ url_for("refresh_selected_feeds") }}' style='display:inline'><button class='btn' type='submit'>Actualizar seleccionados</button></form><form method='post' action='{{ url_for("refresh_all_feeds") }}' style='display:inline'><button class='btn' type='submit'>Actualizar todos</button></form></div><table><thead><tr><th>Título</th><th>Feed</th><th>Nivel</th><th>Categoría</th><th>Fecha</th></tr></thead><tbody>"""]
    for e in results:
        table.append(f"<tr><td><a target='_blank' href='{e['link']}'>{(e['title'] or '')[:100]}</a></td>"
                     f"<td>{e['feed_title']}</td>"
                     f"<td class='threat-{e['threat_level']}'>{e['threat_level']}</td>"
                     f"<td><span class='category-badge category-{e['category']}'>{e['category']}</span></td>"
                     f"<td>{(e['published'] or '')[:16]}</td></tr>")
    table.append("</tbody></table></div>")
    return render_template_string(TEMPLATES['base.html'].replace('{% block content %}{% endblock %}', '{% block content %}'+"".join(table)+'{% endblock %}'))

@app.route("/statistics")
def statistics():
    period = request.args.get("period","30d")
    period_map = {"7d":"-7 days","30d":"-30 days","90d":"-90 days","1y":"-1 year"}
    sqlp = period_map.get(period, "-30 days")
    with closing(get_conn()) as conn:
        total_entries = conn.execute("SELECT COUNT(*) FROM entries WHERE published >= datetime('now', ?)", (sqlp,)).fetchone()[0]
        days = {"7d":7,"30d":30,"90d":90,"1y":365}.get(period,30)
        avg_per_day = total_entries//days if days else 0
        unique_sources = conn.execute("SELECT COUNT(DISTINCT feed_id) FROM entries WHERE published >= datetime('now', ?)", (sqlp,)).fetchone()[0]
        avg_threat_level = conn.execute("SELECT AVG(threat_level) FROM entries WHERE published >= datetime('now', ?)", (sqlp,)).fetchone()[0] or 0
        cats = conn.execute("""
            SELECT category as name, COUNT(*) as count
            FROM entries WHERE published >= datetime('now', ?)
            GROUP BY category ORDER BY count DESC
        """, (sqlp,)).fetchall()
        total_cat = sum(c['count'] for c in cats) or 1
        cats_pct = [{'name':c['name'], 'count':c['count'], 'percentage': (c['count']/total_cat)*100} for c in cats]
    html = ["<h2>Estadísticas</h2>", "<div class='stats-grid'>",
            f"<div class='stat-card'><div class='stat-number'>{total_entries}</div><div class='stat-label'>Entradas en periodo</div></div>",
            f"<div class='stat-card'><div class='stat-number'>{avg_per_day}</div><div class='stat-label'>Media por día</div></div>",
            f"<div class='stat-card'><div class='stat-number'>{unique_sources}</div><div class='stat-label'>Fuentes únicas</div></div>",
            f"<div class='stat-card'><div class='stat-number'>{avg_threat_level:.2f}</div><div class='stat-label'>Nivel medio</div></div>",
            "</div>", "<div class='card'><h3>Por categoría</h3>",
            """<div style='margin-bottom:15px; display:flex; gap:12px;'><form method='post' action='{{ url_for("refresh_selected_feeds") }}' style='display:inline'><button class='btn' type='submit'>Actualizar seleccionados</button></form><form method='post' action='{{ url_for("refresh_all_feeds") }}' style='display:inline'><button class='btn' type='submit'>Actualizar todos</button></form></div><table><thead><tr><th>Categoría</th><th>Entradas</th><th>%</th></tr></thead><tbody>"""]
    for c in cats_pct:
        html.append(f"<tr><td><span class='category-badge category-{c['name']}'>{c['name']}</span></td><td>{c['count']}</td><td>{c['percentage']:.1f}%</td></tr>")
    html.append("</tbody></table></div>")
    return render_template_string(TEMPLATES['base.html'].replace('{% block content %}{% endblock %}', '{% block content %}'+"".join(html)+'{% endblock %}'))

@app.route("/licencica")
def licencica():
    html = [
        "<h2>Licencia</h2>",
        "<div class='card'>",
        "<p><strong>Autor:</strong> José Israel Nadal Vidal</p>",
        "<p><strong>Email:</strong> <a href='mailto:jose.nadal@gmail.com'>jose.nadal@gmail.com</a></p>",
        "<p><strong>Sitio web:</strong> <a href='https://www.israelnadal.com' target='_blank' rel='noopener'>israelnadal.com</a></p>",
        "<p><strong>Licencia:</strong> <a href='https://creativecommons.org/licenses/by-nc-nd/4.0/' target='_blank' rel='noopener'>CC BY-NC-ND 4.0</a></p>",
        "<p>Texto legal completo: <a href='https://creativecommons.org/licenses/by-nc-nd/4.0/legalcode' target='_blank' rel='noopener'>legalcode</a></p>",
        "<p>Resumen legible: <a href='https://creativecommons.org/licenses/by-nc-nd/4.0/' target='_blank' rel='noopener'>creativecommons.org/licenses/by-nc-nd/4.0/</a></p>",
        "<p>Esta obra no permite usos comerciales ni obras derivadas sin autorización expresa por escrito del autor.</p>",
        "</div>"
    ]
    return render_template_string(TEMPLATES['base.html'].replace('{% block content %}{% endblock %}', '{% block content %}' + ''.join(html) + '{% endblock %}'))

# ---------------- Actualización Automática ----------------
def auto_refresh():
    while True:
        time.sleep(3600)
        with closing(get_conn()) as conn, conn:
            feeds = conn.execute("SELECT * FROM feeds WHERE active = 1").fetchall()
            for feed in feeds:
                try:
                    import_feed(conn, feed, verbose=False)
                except Exception as e:
                    print(f"Error actualizando {feed['title']}: {e}")

# ---------------- CLI y Bootstrap ----------------
def bootstrap_if_needed():
    if not os.path.exists(DB_PATH):
        init_db()
    with closing(get_conn()) as conn:
        count = conn.execute("SELECT COUNT(*) FROM feeds").fetchone()[0]
        if count == 0 and os.path.exists(DEFAULT_OPML):
            print("[*] No hay feeds en la base de datos. Importando feeds.opml...")
            try:
                inserted, feeds, errors = import_from_opml(DEFAULT_OPML, analyze=False)
                print(f"[+] Importación completada: {feeds} feeds, {inserted} entradas")
            except Exception as e:
                print(f"[!] Error importando feeds.opml: {e}")

def cli():
    parser = argparse.ArgumentParser(description=f"{APP_NAME} v{VERSION}")
    subparsers = parser.add_subparsers(dest="cmd", required=True)
    subparsers.add_parser("initdb", help="Inicializar base de datos")
    run_parser = subparsers.add_parser("runserver", help="Ejecutar servidor web")
    run_parser.add_argument("--host", default="127.0.0.1", help="Host de escucha")
    run_parser.add_argument("--port", type=int, default=8000, help="Puerto de escucha")
    run_parser.add_argument("--no-debug", action="store_true", help="Desactivar modo debug")
    import_parser = subparsers.add_parser("import", help="Importar feeds desde OPML")
    import_parser.add_argument("opml_file", help="Archivo OPML a importar")
    refresh_parser = subparsers.add_parser("refresh", help="Actualizar feeds")
    refresh_parser.add_argument("--feed-id", type=int, help="ID de feed específico")
    args = parser.parse_args()
    if args.cmd == "initdb":
        init_db(); print(f"[+] Base de datos inicializada en {DB_PATH}")
    elif args.cmd == "runserver":
        bootstrap_if_needed()
        refresh_thread = threading.Thread(target=auto_refresh, daemon=True)
        refresh_thread.start()
        app.run(host=args.host, port=args.port, debug=not args.no_debug, use_reloader=False, threaded=True)
    elif args.cmd == "import":
        if not os.path.exists(args.opml_file):
            print(f"[!] Archivo no encontrado: {args.opml_file}"); sys.exit(1)
        try:
            inserted, feeds, errors = import_from_opml(args.opml_file)
            print(f"[+] Importación completada: {feeds} feeds, {inserted} entradas, {errors} errores")
        except Exception as e:
            print(f"[!] Error: {e}"); sys.exit(1)
    elif args.cmd == "refresh":
        with closing(get_conn()) as conn, conn:
            if args.feed_id:
                feed = conn.execute("SELECT * FROM feeds WHERE id = ?", (args.feed_id,)).fetchone()
                if not feed:
                    print(f"[!] Feed no encontrado: ID {args.feed_id}"); sys.exit(1)
                print(f"[*] Actualizando: {feed['title']}")
                ins, skip, err = import_feed(conn, feed, verbose=True)
                print(f"[+] Completado: {ins} nuevas, {skip} duplicadas, {err} errores")
            else:
                feeds = conn.execute("SELECT * FROM feeds WHERE active = 1").fetchall()
                for feed in feeds:
                    print(f"[*] Actualizando: {feed['title']}")
                    ins, skip, err = import_feed(conn, feed, verbose=False)
                    print(f"  -> {ins} nuevas, {skip} duplicadas, {err} errores")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        bootstrap_if_needed()
        refresh_thread = threading.Thread(target=auto_refresh, daemon=True)
        refresh_thread.start()
        print(f"[*] {APP_NAME} v{VERSION}")
        print(f"[*] Iniciando servidor en http://127.0.0.1:8000")
        print("[*] Presiona Ctrl+C para detener")
        app.run(host="127.0.0.1", port=8000, debug=True, use_reloader=False, threaded=True)
    else:
        cli()
