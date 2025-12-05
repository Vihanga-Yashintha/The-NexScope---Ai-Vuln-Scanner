"""
utils/cve_lookup.py - Robust NVD & OSV lookup with caching and better query fallbacks.
"""

import os
import time
import json
import sqlite3
import logging
import requests
from typing import Optional, List, Dict, Any

# =============================
# Config & Setup
# =============================

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API = "https://api.osv.dev/v1/query"
CACHE_DB = os.path.join("data", "cve_cache.db")
DEFAULT_PAGE_SIZE = 50
MAX_RETRIES = 5
BACKOFF_FACTOR = 1.5
REQUEST_TIMEOUT = 20

os.makedirs("data", exist_ok=True)

logger = logging.getLogger("cve_lookup")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# =============================
# SQLite Cache
# =============================

def _init_cache_db():
    conn = sqlite3.connect(CACHE_DB)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS cves (
        cve_id TEXT PRIMARY KEY,
        raw_json TEXT,
        fetched_at INTEGER
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS queries (
        query_key TEXT PRIMARY KEY,
        result_ids TEXT,
        fetched_at INTEGER
    )""")
    conn.commit()
    conn.close()

def cache_get_cve(cve_id):
    conn = sqlite3.connect(CACHE_DB)
    c = conn.cursor()
    c.execute("SELECT raw_json FROM cves WHERE cve_id=?", (cve_id,))
    row = c.fetchone()
    conn.close()
    if not row: return None
    return json.loads(row[0])

def cache_put_cve(cve_id, raw_json):
    conn = sqlite3.connect(CACHE_DB)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO cves VALUES (?, ?, ?)", (cve_id, json.dumps(raw_json), int(time.time())))
    conn.commit(); conn.close()

def cache_get_query(key):
    conn = sqlite3.connect(CACHE_DB)
    c = conn.cursor()
    c.execute("SELECT result_ids FROM queries WHERE query_key=?", (key,))
    row = c.fetchone(); conn.close()
    if not row: return None
    return json.loads(row[0])

def cache_put_query(key, cve_ids):
    conn = sqlite3.connect(CACHE_DB)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO queries VALUES (?, ?, ?)", (key, json.dumps(cve_ids), int(time.time())))
    conn.commit(); conn.close()

_init_cache_db()

# =============================
# HTTP Helper
# =============================

def _requests_get_with_backoff(url, headers=None, params=None):
    headers = headers or {}
    for i in range(MAX_RETRIES):
        try:
            r = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                return r
            elif r.status_code in (429, 500, 502, 503):
                logger.warning(f"Retry {i+1}: {r.status_code} for {r.url}")
                time.sleep(BACKOFF_FACTOR ** i)
            else:
                logger.warning(f"Unexpected status {r.status_code} for {r.url}: {r.text[:400]}")
                r.raise_for_status()
        except Exception as e:
            logger.warning(f"Request error: {e}")
            time.sleep(BACKOFF_FACTOR ** i)
    raise RuntimeError(f"NVD query failed after {MAX_RETRIES} retries")

def _nvd_headers(api_key=None):
    headers = {"User-Agent": "AiVulnScanner/1.0"}
    if api_key or os.getenv("NVD_API_KEY"):
        headers["apiKey"] = api_key or os.getenv("NVD_API_KEY")
    return headers

# =============================
# NVD Normalization
# =============================

def _normalize_nvd_item(item):
    cve_id = item.get("id") or item.get("cve", {}).get("id")
    desc = ""
    for d in item.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    cvss = None
    try:
        metrics = item.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
    except Exception:
        pass
    return {
        "cve_id": cve_id,
        "summary": desc,
        "cvss_v3": cvss,
        "published": item.get("published"),
        "modified": item.get("lastModified")
    }

# =============================
# Core Query Functions
# =============================

def query_nvd_by_cpe(cpe, api_key=None):
    headers = _nvd_headers(api_key)
    params = {"cpeName": cpe, "startIndex": 0, "resultsPerPage": DEFAULT_PAGE_SIZE}
    r = _requests_get_with_backoff(NVD_BASE, headers, params)
    data = r.json()
    vulns = data.get("vulnerabilities", [])
    results = []
    for v in vulns:
        if "cve" in v:
            results.append(_normalize_nvd_item(v["cve"]))
    return results

def query_nvd_by_keyword(keyword, api_key=None):
    headers = _nvd_headers(api_key)
    params = {"keywordSearch": keyword, "startIndex": 0, "resultsPerPage": DEFAULT_PAGE_SIZE}
    r = _requests_get_with_backoff(NVD_BASE, headers, params)
    data = r.json()
    vulns = data.get("vulnerabilities", [])
    results = []
    for v in vulns:
        if "cve" in v:
            results.append(_normalize_nvd_item(v["cve"]))
    return results

# =============================
# Public Function
# =============================

def get_cves_for_service(service, version=None, api_key=None):
    if service.startswith("cpe:"):
        vulns = query_nvd_by_cpe(service, api_key)
    else:
        keyword = f"{service} {version or ''}".strip()
        vulns = query_nvd_by_keyword(keyword, api_key)
    return {"source": "nvd", "cves": vulns}

# =============================
# Manual Test
# =============================

if __name__ == "__main__":
    print(query_nvd_by_cpe("cpe:/a:vsftpd:vsftpd:2.3.4"))
