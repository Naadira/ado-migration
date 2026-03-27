import os
from dotenv import load_dotenv
import re
import time
import xml.etree.ElementTree as ET
import pandas as pd
import json
from html import unescape
import re
import json
import html
import mimetypes
from datetime import datetime, timezone
import requests
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
from requests.auth import HTTPBasicAuth
from bs4 import BeautifulSoup
from bs4 import NavigableString
from bs4 import NavigableString, Tag
from typing import Dict, List, Tuple, Set

load_dotenv()

# -------------------
# CONFIGURATION
# -------------------

ADO_ORG = os.getenv("ADO_ORG")
ADO_PROJECT = os.getenv("ADO_PROJECT")
ADO_PAT = os.getenv("ADO_PAT")

JIRA_URL = os.getenv("JIRA_URL")
JIRA_EMAIL = os.getenv("JIRA_EMAIL")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY")

Email = os.getenv("EMAIL")
JIRA_ACCOUNT_ID = os.getenv("JIRA_ACCOUNT_ID")

WORKITEM_TYPE_MAP = {
    "Defect": "Defect",
}

PRIORITY_MAP = {1: "Blocker", 2: "High", 3: "Low", 4: "Trivial"}

BUG_PRIORITY_MAP = {
    "P1": "Blocker", "P2": "High", "P3": "Low", "P4": "Trivial",
}

RESOLUTION_MAP = {
    "As Designed": "Working As Expected",
    "Cannot Reproduce": "Cannot Reproduce",
    "Copied to Backlog": "Copied to Backlog",
    "Deferred": "Deferred",
    "Duplicate": "Duplicate",
    "Fixed": "Done",
    "Fixed and verified": "Done",
    "Obsolete": "Known Error",
    "Will not Fix": "Won't Do"
}

STATE_MAP = {
    "New": "New",
    "Under Investigation": "In Refinement",
    "Ready": "Ready",
    "In Development": "In Progress",
    "Development Complete": "Review",
    "In Test": "Testing",
    "Test Complete": "Ready to Release",
    "Closed": "Done",
    "Removed": "Cancelled",
    "Waiting for customer": "Waiting for customer"
}

USER_MAP_FILE = "ado_jira_user_map.csv"


def _load_user_map(filepath: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if not os.path.exists(filepath):
        print(f"⚠️  User map file not found: {filepath}")
        return result
    try:
        with open(filepath, "r", encoding="utf-8-sig") as fh:
            first_line = fh.readline()
            delimiter = "\t" if "\t" in first_line else ","
            fh.seek(0)
            import csv
            reader = csv.reader(fh, delimiter=delimiter)
            for row_num, row in enumerate(reader, 1):
                if not row or all(cell.strip() == "" for cell in row):
                    continue
                if len(row) < 2:
                    continue
                email = row[0].strip().lower()
                account_id = row[1].strip()
                if row_num == 1 and ("@" not in email):
                    continue
                if email and account_id:
                    result[email] = account_id
        print(f"✅ Loaded {len(result)} user mappings from {filepath}")
    except Exception as e:
        print(f"❌ Failed to load user map from {filepath}: {e}")
    return result


USER_MAP: Dict[str, str] = _load_user_map(USER_MAP_FILE)

WIQL_PAGE_SIZE = 200
SLEEP_BETWEEN_CALLS = 0.2
MAPPING_FILE = "ado_jira_mapping.json"
ATTACH_DIR = "ado_attachments"
ATTACH_URL_SUBSTR = "/_apis/wit/attachments/"
MAX_RETRIES = 5
RETRY_BACKOFF = 2


def api_request(method: str, url: str, wi_id=None, issue_key=None, step="API Call", **kwargs) -> requests.Response:
    func = getattr(requests, method.lower())
    wait = RETRY_BACKOFF
    for attempt in range(1, MAX_RETRIES + 2):
        try:
            r = func(url, **kwargs)
            if r.status_code == 429:
                retry_after = int(r.headers.get("Retry-After", wait))
                log(f"   ⏳ Rate limited (429). Waiting {retry_after}s before retry {attempt}/{MAX_RETRIES}...")
                if attempt > MAX_RETRIES:
                    return r
                time.sleep(retry_after)
                wait = min(wait * 2, 60)
                continue
            elif r.status_code >= 500:
                log(f"   ⚠️ Server error ({r.status_code}). Retry {attempt}/{MAX_RETRIES}...")
                if attempt > MAX_RETRIES:
                    return r
                time.sleep(wait)
                wait = min(wait * 2, 60)
                continue
            return r
        except requests.exceptions.ConnectionError as e:
            log(f"   ⚠️ Connection error on attempt {attempt}: {e}")
            if attempt > MAX_RETRIES:
                raise
            time.sleep(wait)
            wait = min(wait * 2, 60)
    raise RuntimeError(f"api_request failed after {MAX_RETRIES} retries for {url}")


def ado_auth():
    return ("", ADO_PAT)


def jira_auth():
    return HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN)


def clean_base(url: str) -> str:
    return (url or "").rstrip("/")


def chunked(iterable, size):
    for i in range(0, len(iterable), size):
        yield iterable[i:i + size]


def log(msg):
    print(msg, flush=True)


def ensure_dir(path: str):
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)


def sanitize_filename(name: str) -> str:
    if not name:
        return "attachment"
    name = os.path.basename(name)
    name = re.sub(r'[\\/:*?"<>|]+', "_", name)
    name = name.strip().strip(".")
    if not name:
        name = "attachment"
    return name


def unique_path(root_dir: str, filename: str) -> str:
    filename = sanitize_filename(filename)
    base, ext = os.path.splitext(filename)
    candidate = os.path.join(root_dir, filename)
    i = 1
    while os.path.exists(candidate):
        candidate = os.path.join(root_dir, f"{base} ({i}){ext}")
        i += 1
    return candidate


def clean_html_to_text(s: str) -> str:
    if not s:
        return ""
    s = html.unescape(s)
    s = s.replace("\xa0", " ")
    s = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n", s)
    s = re.sub(r"(?i)</\s*p\s*>", "\n\n", s)
    s = re.sub(r"(?i)<\s*p\s*>", "", s)
    s = re.sub(r"<[^>]+>", "", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def to_adf_paragraph(text: str) -> Dict:
    safe_text = text or ""
    return {"type": "paragraph", "content": [{"type": "text", "text": safe_text}] if safe_text else []}


def to_adf_doc(text: str) -> Dict:
    paras = [p for p in re.split(r"\n{2,}", text or "") if p is not None]
    content = [to_adf_paragraph(p) for p in paras] if paras else [to_adf_paragraph("")]
    return {"type": "doc", "version": 1, "content": content}


def get_jira_account_id_for_email(email: str) -> str:
    if not email:
        return ""
    return USER_MAP.get(email.lower(), None)


def convert_ado_datetime(ado_datetime_str):
    if not ado_datetime_str:
        return None
    try:
        dt = datetime.strptime(ado_datetime_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
    except ValueError:
        pass
    try:
        dt = datetime.strptime(ado_datetime_str, "%Y-%m-%dT%H:%M:%SZ")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
    except ValueError:
        pass
    try:
        dt = datetime.strptime(ado_datetime_str, "%d/%m/%Y %H:%M")
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
    except ValueError:
        pass
    try:
        dt = datetime.strptime(ado_datetime_str, "%d/%m/%Y")
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
    except ValueError:
        return None


# ---------- ADO fetch ----------
def ado_wiql_all_ids(query: str) -> List[int]:
    print(query, "")
    url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/wiql?api-version=7.1-preview.2"
    r = api_request("post", url, step="WIQL Query", json={"query": query}, auth=ado_auth())
    print("Status:", r.status_code)
    r.raise_for_status()
    items = r.json().get("workItems", [])
    return [wi["id"] for wi in items]


def ado_get_workitems_by_ids(ids: List[int]) -> List[Dict]:
    if not ids:
        return []
    url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/workitems?api-version=7.0&$expand=all&ids={','.join(map(str, ids))}"
    r = api_request("get", url, step="Fetch WorkItems", auth=ado_auth())
    r.raise_for_status()
    return r.json().get("value", [])


def ado_get_comments(wi_id: int) -> List[Dict]:
    url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/workItems/{wi_id}/comments?api-version=7.0-preview.3"
    r = api_request("get", url, wi_id=wi_id, step="Fetch Comments", auth=ado_auth())
    if r.status_code == 200:
        return r.json().get("comments", [])
    else:
        log(f"   ⚠️ Comments fetch failed for {wi_id}: {r.status_code}")
        return []


# ============================================================
# ADO IDENTITY LOOKUP — resolves GUIDs to display names
# ============================================================
_ADO_IDENTITY_CACHE: Dict[str, str] = {}


def _fetch_ado_identities_batch(guids: List[str]) -> Dict[str, str]:
    if not guids:
        return {}

    to_fetch = [g for g in guids if g.lower() not in _ADO_IDENTITY_CACHE]
    if not to_fetch:
        return {g.lower(): _ADO_IDENTITY_CACHE[g.lower()]
                for g in guids if _ADO_IDENTITY_CACHE.get(g.lower())}

    result: Dict[str, str] = {}
    for batch in [to_fetch[i:i+20] for i in range(0, len(to_fetch), 20)]:
        ids_param = ",".join(batch)
        url = (
            f"https://vssps.dev.azure.com/{ADO_ORG}/_apis/identities"
            f"?identityIds={ids_param}&api-version=7.1"
        )
        try:
            r = requests.get(url, auth=ado_auth(), timeout=15)
            if r.status_code == 200:
                data = r.json()
                identities = data if isinstance(data, list) else data.get("value", [])
                for identity in identities:
                    identity_id = (identity.get("id") or "").lower()
                    name = (
                        identity.get("providerDisplayName")
                        or identity.get("customDisplayName")
                        or ""
                    )
                    if identity_id and name:
                        _ADO_IDENTITY_CACHE[identity_id] = name
                        result[identity_id] = name
                        log(f"   👤 Resolved GUID {identity_id} → {name}")
            else:
                log(f"   ⚠️ Identity batch API returned {r.status_code}: {r.text[:120]}")
        except Exception as e:
            log(f"   ⚠️ Identity batch fetch failed: {e}")

    for g in to_fetch:
        if g.lower() not in _ADO_IDENTITY_CACHE:
            _ADO_IDENTITY_CACHE[g.lower()] = ""

    return result


def _fetch_ado_identity_display_name(guid: str) -> str:
    guid_lower = guid.lower()
    if guid_lower in _ADO_IDENTITY_CACHE:
        return _ADO_IDENTITY_CACHE[guid_lower]
    batch_result = _fetch_ado_identities_batch([guid])
    return batch_result.get(guid_lower, "")


IMG_SRC_RE = re.compile(r'(?is)<img[^>]+src=["\']([^"\']+)["\']')
HREF_RE = re.compile(r'(?is)<a[^>]+href=["\']([^"\']+)["\']')

_ADO_GUID_RE = re.compile(
    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
)


def _build_mention_map_from_comment(comment: Dict) -> Dict[str, str]:
    guids = [
        m.get("artifactId", "").strip()
        for m in (comment.get("mentions") or [])
        if m.get("artifactType") == "Person" and m.get("artifactId", "").strip()
    ]
    if not guids:
        return {}

    mention_map = _fetch_ado_identities_batch(guids)

    for guid in guids:
        if not mention_map.get(guid.lower()):
            log(f"   ⚠️ Could not resolve display name for GUID: {guid}")

    return mention_map


_MARKDOWN_MENTION_RE = re.compile(
    r'@<([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})>'
)


def _resolve_markdown_mentions(text: str, mention_map: Dict[str, str]) -> str:
    """Resolve markdown mentions and unescape HTML entities including emoji."""
    import html as html_lib

    # First unescape HTML entities (&quot; -> ", &amp; -> &, etc)
    text = html_lib.unescape(text)

    guid_map = _get_ado_guid_map()

    def replace_mention(m):
        guid = m.group(1)
        guid_lower = guid.lower()

        jira_acct = guid_map.get(guid_lower)
        if jira_acct:
            return f"[~accountId:{jira_acct}]"

        display_name = mention_map.get(guid_lower, "")
        if display_name:
            return f"@{display_name}"

        display_name = _fetch_ado_identity_display_name(guid)
        if display_name:
            return f"@{display_name}"

        return "@Unknown"

    return _MARKDOWN_MENTION_RE.sub(replace_mention, text)


# ============================================================
# IMPROVED _convert_markdown_to_jira_wiki (from Code 1)
# Handles: ATX headings, GFM pipe tables, unordered/ordered
# lists, bold, italic, inline code, markdown links, bare URLs.
# ============================================================

_BOLD_START = '\x00B\x00'
_BOLD_END   = '\x00E\x00'


def _inline_md_to_jira(text: str) -> str:
    """Apply inline markdown → Jira wiki conversions to a single line/span."""

    # 1. Protect inline code: `code` → {{code}}
    text = re.sub(r'`([^`]+)`', r'{{\1}}', text)

    # 2. Bold+italic ***text*** → *_text_*  (must precede bold/italic separately)
    text = re.sub(r'\*{3}(.+?)\*{3}', r'*_\1_*', text)

    # 3. Bold **text** → placeholder sentinels so the italic step won't re-consume them
    text = re.sub(r'\*{2}(.+?)\*{2}',
                  lambda m: _BOLD_START + m.group(1) + _BOLD_END, text)

    # 4. Italic *text* → _text_  (only single * remain now)
    text = re.sub(r'\*([^*\n]+)\*', r'_\1_', text)

    # 5. Restore bold sentinels → Jira *bold*
    text = text.replace(_BOLD_START, '*').replace(_BOLD_END, '*')

    # 6. Markdown links: [text](url) → [text|url]
    #    NOT image links (those start with !) — already extracted upstream
    def md_link_to_jira(m):
        link_text = m.group(1)
        url = m.group(2).rstrip('>').strip()
        # If display text IS the URL, emit bare [url] (no duplicate text)
        if link_text.startswith('http') and link_text.rstrip('>') == url:
            return f'[{url}]'
        return f'[{link_text}|{url}]'

    text = re.sub(r'(?<!!)\[([^\]]+)\]\(([^)]+)\)', md_link_to_jira, text)

    # 7. Bare angle-bracket URLs: <https://...> → [https://...]
    text = re.sub(r'<(https?://[^>]+)>', r'[\1]', text)

    return text


def _convert_markdown_to_jira_wiki(text: str) -> str:
    """
    Convert GitHub-flavoured markdown to Jira wiki markup.

    Handles:
      - ATX headings: ### Heading  → h3. Heading
      - GFM pipe tables: | col | → Jira || col ||
      - Unordered lists: * item / - item  → * item  (Jira wiki bullet)
      - Ordered lists: 1. item → # item
      - Bold: **text**  → *text*
      - Italic: *text* (single) → _text_
      - Inline code: `code`  → {{code}}
      - Markdown links: [text](url)  → [text|url]
      - Bare URLs: https://...  → left as-is (Jira auto-links)
    """
    lines = text.split('\n')
    out = []
    i = 0

    while i < len(lines):
        line = lines[i].rstrip()

        # --- Detect GFM pipe table block ---
        if re.match(r'^\s*\|', line):
            table_lines = []
            while i < len(lines) and re.match(r'^\s*\|', lines[i].rstrip()):
                table_lines.append(lines[i].rstrip())
                i += 1

            first_row = True
            for tline in table_lines:
                if re.match(r'^\s*\|[\s\-\|:]+\|\s*$', tline):
                    continue
                cells = re.split(r'\s*\|\s*', tline.strip().strip('|'))
                jira_cells = []
                for cell in cells:
                    cell = re.sub(r'\s*<br\s*/?>\s*', ' ', cell, flags=re.IGNORECASE).strip()
                    cell = _inline_md_to_jira(cell)
                    jira_cells.append(cell)
                if first_row:
                    out.append('||' + '||'.join(jira_cells) + '||')
                    first_row = False
                else:
                    out.append('|' + '|'.join(jira_cells) + '|')
            continue

        # --- ATX headings: ### Text → h3. Text ---
        heading_match = re.match(r'^(#{1,6})\s+(.+)$', line)
        if heading_match:
            level = len(heading_match.group(1))
            heading_text = re.sub(r'\s*#+\s*$', '', heading_match.group(2).strip())
            heading_text = _inline_md_to_jira(heading_text)
            out.append(f'h{level}. {heading_text}')
            i += 1
            continue

        # --- Unordered list items: * item / - item / + item ---
        bullet_match = re.match(r'^(\s*)[\*\-\+]\s+(.+)$', line)
        if bullet_match:
            depth = (len(bullet_match.group(1)) // 2) + 1
            item_text = _inline_md_to_jira(bullet_match.group(2))
            out.append('*' * depth + ' ' + item_text)
            i += 1
            continue

        # --- Ordered list items: 1. item ---
        ordered_match = re.match(r'^(\s*)\d+\.\s+(.+)$', line)
        if ordered_match:
            depth = (len(ordered_match.group(1)) // 2) + 1
            item_text = _inline_md_to_jira(ordered_match.group(2))
            out.append('#' * depth + ' ' + item_text)
            i += 1
            continue

        # --- Regular paragraph line — apply inline formatting ---
        out.append(_inline_md_to_jira(line))
        i += 1

    return '\n'.join(out)


def extract_inline_ado_urls(html_str: str) -> List[str]:
    urls = []
    for u in IMG_SRC_RE.findall(html_str or ""):
        if ATTACH_URL_SUBSTR in u:
            urls.append(u)
    for u in HREF_RE.findall(html_str or ""):
        if ATTACH_URL_SUBSTR in u:
            urls.append(u)
    seen: Set[str] = set()
    uniq: List[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


# ---------- Attachment download/upload ----------
def _with_download_params(u: str, api_version: str = "7.0") -> str:
    p = urlparse(u)
    q = parse_qs(p.query)
    if "api-version" not in q:
        q["api-version"] = [api_version]
    if "download" not in q:
        q["download"] = ["true"]
    new_q = urlencode({k: v[0] if isinstance(v, list) and len(v) == 1 else v for k, v in q.items()}, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))


def ado_download_attachment(att_url: str, desired_filename: str, wi_id=None, issue_key=None) -> str:
    ensure_dir(ATTACH_DIR)
    local_path = unique_path(ATTACH_DIR, desired_filename)
    candidates = [
        _with_download_params(att_url, "7.0"),
        _with_download_params(att_url, "6.0"),
        att_url
    ]
    headers = {"Accept": "application/octet-stream"}
    for idx, url_try in enumerate(candidates, 1):
        try:
            r = api_request("get", url_try, wi_id=wi_id, issue_key=issue_key,
                            step=f"Download Attachment ({desired_filename})",
                            auth=ado_auth(), headers=headers, stream=True, allow_redirects=True)
            if r.status_code == 200:
                with open(local_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                log_to_excel(wi_id, issue_key, "Download Attachment", "Success",
                             f"Downloaded {desired_filename} (attempt {idx})")
                return local_path
            else:
                log(f"   ⚠️ Download attempt {idx} failed ({r.status_code})")
        except Exception as e:
            log(f"   ⚠️ Download attempt {idx} error: {e}")
    return ""


def jira_upload_attachment(issue_key: str, file_path: str, wi_id=None) -> dict:
    if not file_path or not os.path.exists(file_path):
        return None
    base = clean_base(JIRA_URL)
    url = f"{base}/rest/api/3/issue/{issue_key}/attachments"
    headers = {"X-Atlassian-Token": "no-check"}
    with open(file_path, "rb") as fh:
        files = {"file": (os.path.basename(file_path), fh,
                          mimetypes.guess_type(file_path)[0] or "application/octet-stream")}
        r = api_request("post", url, wi_id=wi_id, issue_key=issue_key,
                        step=f"Upload Attachment ({os.path.basename(file_path)})",
                        headers=headers, auth=jira_auth(), files=files)
    try:
        payload = r.json()
    except Exception:
        payload = None
    if r.status_code not in (200, 201):
        log(f"⚠️ Failed to upload {file_path}: {r.status_code}")
        return None
    if isinstance(payload, list) and len(payload) > 0:
        info = payload[0]
    elif isinstance(payload, dict):
        info = payload
    else:
        return None
    media_id = info.get("mediaId") or info.get("mediaIdString")
    numeric_id = str(info.get("id")) if info.get("id") is not None else None
    filename = info.get("filename") or os.path.basename(file_path)
    content_url = info.get("content") or info.get("url") or None
    log_to_excel(wi_id, issue_key, "Upload Attachment", "Success", f"Uploaded {filename} (ID: {numeric_id})")
    return {"mediaId": media_id, "id": numeric_id, "filename": filename, "content": content_url, "raw": info}


def jira_upload_attachment_as_comment(issue_key, url_content, data, wi_id=None):
    base = clean_base(JIRA_URL)
    url = f"{base}/rest/api/2/issue/{issue_key}/comment"
    body = f"!{url_content.get('content')}!" if data == " " else f"{data} !{url_content.get('content')}!"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    r = api_request("post", url, wi_id=wi_id, issue_key=issue_key,
                    step="Upload Attachment as Comment",
                    auth=jira_auth(), headers=headers, json={"body": body})
    if r.status_code not in (200, 201):
        log(f"   ⚠️ Upload attachment as comment failed: {r.status_code}")


# ---------- Jira issue + comments ----------
def jira_create_issue(fields: Dict, wi_id=None) -> str:
    base = clean_base(JIRA_URL)
    url = f"{base}/rest/api/3/issue"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    def _attempt(payload_fields):
        return api_request("post", url, wi_id=wi_id, step="Create Issue",
                           auth=jira_auth(), headers=headers, json={"fields": payload_fields})

    r = _attempt(fields)
    if r.status_code == 400:
        try:
            error_body = r.json()
        except Exception:
            error_body = {}
        field_errors = error_body.get("errors", {})
        bad_fields = {"assignee", "reporter"} & set(field_errors.keys())
        if bad_fields:
            for bad in bad_fields:
                log(f"   ⚠️ Jira rejected '{bad}'. Retrying without it.")
                log_to_excel(wi_id, None, f"Create Issue – {bad.title()}", "Warning",
                             f"Removed '{bad}' — not permitted in project.")
            retry_fields = {k: v for k, v in fields.items() if k not in bad_fields}
            r = _attempt(retry_fields)
    if r.status_code == 201:
        key = r.json().get("key")
        log(f"✅ Created {key}")
        log_to_excel(wi_id, key, "Create Issue", "Success", f"Jira issue {key} created")
        return key
    else:
        log(f"❌ Issue create failed: {r.status_code} {r.text}")
        log_to_excel(wi_id, None, "Create Issue", "Failed", f"HTTP {r.status_code}: {r.text[:100]}")
        return ""


def jira_add_comment(issue_key: str, text: str, wi_id=None):
    if not text:
        return
    base = clean_base(JIRA_URL)
    url = f"{base}/rest/api/3/issue/{issue_key}/comment"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    payload = {"body": to_adf_doc(text)}
    r = api_request("post", url, wi_id=wi_id, issue_key=issue_key,
                    step="Add Comment", auth=jira_auth(), headers=headers, json=payload)
    if r.status_code not in (200, 201):
        log(f"   ⚠️ Add comment failed: {r.status_code}")


URL_PATTERN = re.compile(r'(https?://\S+)')


# ============================================================================
# INTEGRATED TABLE CONVERSION FUNCTIONS (from Code 1)
# ============================================================================

def _extract_cell_content(cell: Tag) -> List[Dict]:
    """
    Extract content from a table cell and return as ADF paragraph content.
    Handles: text, links, bold, italic, line breaks, etc.
    """
    content = []

    def process_node(node):
        if isinstance(node, NavigableString):
            text = str(node).strip()
            if text:
                content.append({"type": "text", "text": text})
            return

        if not isinstance(node, Tag):
            return

        name = node.name.lower() if node.name else None

        if name == "br":
            content.append({"type": "hardBreak"})
        elif name in ["b", "strong"]:
            text = node.get_text(strip=True)
            if text:
                content.append({
                    "type": "text",
                    "text": text,
                    "marks": [{"type": "strong"}]
                })
        elif name in ["i", "em"]:
            text = node.get_text(strip=True)
            if text:
                content.append({
                    "type": "text",
                    "text": text,
                    "marks": [{"type": "em"}]
                })
        elif name == "a":
            href = node.get("href", "").strip()
            text = node.get_text(strip=True) or href
            if href and text:
                content.append({
                    "type": "text",
                    "text": text,
                    "marks": [{"type": "link", "attrs": {"href": href}}]
                })
            elif text:
                content.append({"type": "text", "text": text})
        elif name == "p":
            for child in node.children:
                process_node(child)
        elif name == "div":
            for child in node.children:
                process_node(child)
        elif name == "span":
            for child in node.children:
                process_node(child)
        else:
            for child in node.children:
                process_node(child)

    for child in cell.children:
        process_node(child)

    if not content:
        text = cell.get_text(strip=True)
        if text:
            content.append({"type": "text", "text": text})

    return content if content else [{"type": "text", "text": ""}]


def improved_process_description_to_adf(issue_key: str, raw_html: str, wi_id=None) -> dict:
    """
    Enhanced description processor that walks the full DOM in document order,
    preserving ALL content: paragraphs, divs, bold/italic text, inline spans,
    tables, code blocks (monospace spans), images, and links.

    Previously only tables were emitted — all surrounding text was silently dropped.
    This version processes every node in the order it appears in the HTML.
    """
    if not raw_html or not raw_html.strip():
        return {"type": "doc", "version": 1, "content": []}

    soup = BeautifulSoup(raw_html, "html.parser")

    # If there are no tables at all, delegate to the original processor
    if not soup.find("table"):
        return process_description_to_adf(issue_key, raw_html, wi_id=wi_id)

    adf_content = []
    # Buffer for inline text nodes that haven't been flushed into a paragraph yet
    inline_buf: List[Dict] = []

    def flush_inline():
        """Flush any accumulated inline nodes as a paragraph block."""
        if inline_buf:
            adf_content.append({"type": "paragraph", "content": inline_buf.copy()})
            inline_buf.clear()

    def make_inline_nodes(element) -> List[Dict]:
        """
        Recursively extract inline ADF nodes from an element.
        Handles: text, <b>/<strong>, <i>/<em>, <u>, <a>, <br>, <span>, <code>.
        """
        nodes = []
        for child in element.children:
            if isinstance(child, NavigableString):
                text = html.unescape(str(child)).replace("\xa0", " ")
                if text.strip() or text == " ":
                    nodes.append({"type": "text", "text": text})
            elif isinstance(child, Tag):
                name = (child.name or "").lower()
                if name == "br":
                    nodes.append({"type": "hardBreak"})
                elif name in ("b", "strong"):
                    text = child.get_text()
                    if text.strip():
                        nodes.append({"type": "text", "text": text,
                                      "marks": [{"type": "strong"}]})
                elif name in ("i", "em"):
                    text = child.get_text()
                    if text.strip():
                        nodes.append({"type": "text", "text": text,
                                      "marks": [{"type": "em"}]})
                elif name == "u":
                    text = child.get_text()
                    if text.strip():
                        nodes.append({"type": "text", "text": text,
                                      "marks": [{"type": "underline"}]})
                elif name == "code":
                    text = child.get_text()
                    if text.strip():
                        nodes.append({"type": "text", "text": text,
                                      "marks": [{"type": "code"}]})
                elif name == "a":
                    href = (child.get("href") or "").strip()
                    label = child.get_text(strip=True) or href
                    if href:
                        nodes.append({"type": "text", "text": label,
                                      "marks": [{"type": "link", "attrs": {"href": href}}]})
                    elif label:
                        nodes.append({"type": "text", "text": label})
                elif name == "span":
                    # Detect monospace/code-style spans (stack traces etc.)
                    style = (child.get("style") or "").lower()
                    is_mono = any(k in style for k in ("monospace", "courier", "consolas", "font-family:consolas"))
                    if is_mono:
                        raw = child.get_text().replace("\xa0", " ").strip()
                        if raw:
                            # Emit as a code block — flush inline first
                            nodes_copy = nodes.copy()
                            nodes.clear()
                            # Return what we have so far, let caller flush, then add code block
                            # We use a sentinel to signal a block-level code node
                            nodes.extend(nodes_copy)
                            nodes.append({"__block__": "codeBlock", "text": raw})
                    else:
                        nodes.extend(make_inline_nodes(child))
                elif name == "img":
                    src = (child.get("src") or "").strip()
                    if src and ATTACH_URL_SUBSTR in src:
                        local_file = download_images_to_ado_attachments(
                            src, wi_id=wi_id, issue_key=issue_key)
                        if local_file:
                            upload = jira_upload_attachment(issue_key, local_file, wi_id=wi_id)
                            if upload and upload.get("id"):
                                nodes.append({"__block__": "mediaSingle",
                                              "url": f"{JIRA_URL}/rest/api/2/attachment/content/{upload['id']}"})
                    elif src:
                        nodes.append({"type": "text", "text": src,
                                      "marks": [{"type": "link", "attrs": {"href": src}}]})
                else:
                    nodes.extend(make_inline_nodes(child))
        return nodes

    def _is_mono_span(node) -> bool:
        """True if this node is a monospace/code-style span or pre element."""
        if not isinstance(node, Tag):
            return False
        name = (node.name or "").lower()
        if name == "pre":
            return True
        if name == "span":
            style = (node.get("style") or "").lower()
            return any(k in style for k in ("monospace", "courier", "consolas"))
        return False

    def process_table(table_elem) -> Dict:
        """Convert an HTML table element to an ADF table node.
        Skips rows and columns that are entirely empty (caused by ADO rowspan/colspan markup).
        """
        table_rows = []

        # First pass: collect all rows with their real cell count
        all_rows = table_elem.find_all("tr")

        # Track which column indices have ANY content across all rows
        # so we can drop entirely-empty columns too
        col_has_content = {}

        raw_rows = []
        for tr in all_rows:
            tds = tr.find_all(["td", "th"])
            row_data = []
            for col_idx, td in enumerate(tds):
                text = td.get_text(separator=" ", strip=True)
                # Also check for images
                has_img = bool(td.find("img"))
                has_content = bool(text) or has_img
                row_data.append((td, has_content))
                if has_content:
                    col_has_content[col_idx] = True
            raw_rows.append(row_data)

        # Identify columns that have content in at least one row
        # (This handles phantom extra columns from colspan/rowspan)
        max_cols = max((len(r) for r in raw_rows), default=0)
        # A column is "real" if it has content anywhere OR if it's the only column
        real_col_indices = {i for i in range(max_cols) if col_has_content.get(i, False)}
        # If NO columns have content at all, keep all (edge case)
        if not real_col_indices:
            real_col_indices = set(range(max_cols))

        for tr, row_data in zip(all_rows, raw_rows):
            # Skip rows where ALL cells are empty
            if not any(has_content for _, has_content in row_data):
                continue

            is_header_row = bool(tr.find("th"))
            row_cells = []

            for col_idx, (td, has_content) in enumerate(row_data):
                # Skip columns that are empty everywhere
                if col_idx not in real_col_indices:
                    continue

                cell_type = "tableHeader" if (td.name == "th" or is_header_row) else "tableCell"
                cell_content = _extract_cell_content(td)
                row_cells.append({
                    "type": cell_type,
                    "content": [{"type": "paragraph", "content": cell_content}]
                })

            if row_cells:
                table_rows.append({"type": "tableRow", "content": row_cells})

        if table_rows:
            return {
                "type": "table",
                "attrs": {"isNumberColumnEnabled": False, "layout": "default"},
                "content": table_rows
            }
        return None

    def walk(node):
        """Walk a DOM node and emit ADF block nodes into adf_content."""
        if isinstance(node, NavigableString):
            text = html.unescape(str(node)).replace("\xa0", " ")
            if text.strip():
                inline_buf.append({"type": "text", "text": text})
            return

        if not isinstance(node, Tag):
            return

        name = (node.name or "").lower()

        # ---- TABLE — flush inline buffer first, then emit table block ----
        if name == "table":
            flush_inline()
            tbl = process_table(node)
            if tbl:
                adf_content.append(tbl)
            return

        # ---- PRE / monospace SPAN — code block ----
        if _is_mono_span(node):
            flush_inline()
            raw = node.get_text().replace("\xa0", " ").strip()
            if raw:
                adf_content.append({
                    "type": "codeBlock",
                    "attrs": {"language": ""},
                    "content": [{"type": "text", "text": raw}]
                })
            return

        # ---- IMG — flush then emit mediaSingle ----
        if name == "img":
            src = (node.get("src") or "").strip()
            if src and ATTACH_URL_SUBSTR in src:
                flush_inline()
                local_file = download_images_to_ado_attachments(
                    src, wi_id=wi_id, issue_key=issue_key)
                if local_file:
                    upload = jira_upload_attachment(issue_key, local_file, wi_id=wi_id)
                    if upload and upload.get("id"):
                        adf_content.append({
                            "type": "mediaSingle",
                            "content": [{"type": "media", "attrs": {
                                "type": "external",
                                "url": f"{JIRA_URL}/rest/api/2/attachment/content/{upload['id']}",
                                "width": 710, "height": 163
                            }}]
                        })
            elif src:
                inline_buf.append({"type": "text", "text": src,
                                   "marks": [{"type": "link", "attrs": {"href": src}}]})
            return

        # ---- BR — inline line break ----
        if name == "br":
            inline_buf.append({"type": "hardBreak"})
            return

        # ---- Inline formatting tags — accumulate into buffer ----
        if name in ("b", "strong"):
            text_only_children = all(
                isinstance(c, NavigableString) or (isinstance(c, Tag) and c.name in ("br",))
                for c in node.children
            )
            if text_only_children:
                text = node.get_text()
                if text.strip():
                    inline_buf.append({"type": "text", "text": text,
                                    "marks": [{"type": "strong"}]})
            else:
                # Has non-text children (e.g. <img>) — recurse so they aren't dropped
                for child in node.children:
                    walk(child)
            return

        if name in ("i", "em"):
            text_only_children = all(
                isinstance(c, NavigableString) or (isinstance(c, Tag) and c.name in ("br",))
                for c in node.children
            )
            if text_only_children:
                text = node.get_text()
                if text.strip():
                    inline_buf.append({"type": "text", "text": text,
                                    "marks": [{"type": "em"}]})
            else:
                for child in node.children:
                    walk(child)
            return

        if name == "u":
            text_only_children = all(
                isinstance(c, NavigableString) or (isinstance(c, Tag) and c.name in ("br",))
                for c in node.children
            )
            if text_only_children:
                text = node.get_text()
                if text.strip():
                    inline_buf.append({"type": "text", "text": text,
                                    "marks": [{"type": "underline"}]})
            else:
                for child in node.children:
                    walk(child)
            return

        if name == "a":
            href = (node.get("href") or "").strip()
            label = node.get_text(strip=True) or href
            if href:
                inline_buf.append({"type": "text", "text": label,
                                   "marks": [{"type": "link", "attrs": {"href": href}}]})
            elif label:
                inline_buf.append({"type": "text", "text": label})
            return

        if name == "span":
            style = (node.get("style") or "").lower()
            is_mono = any(k in style for k in ("monospace", "courier", "consolas"))
            if is_mono:
                flush_inline()
                raw = node.get_text().replace("\xa0", " ").strip()
                if raw:
                    adf_content.append({
                        "type": "codeBlock",
                        "attrs": {"language": ""},
                        "content": [{"type": "text", "text": raw}]
                    })
                return
            # Regular span — recurse into children
            for child in node.children:
                walk(child)
            return

        # ---- Block tags: P, DIV, H1-H6, BLOCKQUOTE, SECTION ----
        if name in ("p", "blockquote", "section", "article"):
            flush_inline()
            local_inline: List[Dict] = []
            for child in node.children:
                if isinstance(child, NavigableString):
                    text = html.unescape(str(child)).replace("\xa0", " ")
                    if text.strip() or text == " ":
                        local_inline.append({"type": "text", "text": text})
                elif isinstance(child, Tag):
                    cname = (child.name or "").lower()
                    if cname == "br":
                        local_inline.append({"type": "hardBreak"})
                    elif cname in ("b", "strong"):
                        t = child.get_text()
                        if t.strip():
                            local_inline.append({"type": "text", "text": t,
                                                 "marks": [{"type": "strong"}]})
                    elif cname in ("i", "em"):
                        t = child.get_text()
                        if t.strip():
                            local_inline.append({"type": "text", "text": t,
                                                 "marks": [{"type": "em"}]})
                    elif cname == "u":
                        t = child.get_text()
                        if t.strip():
                            local_inline.append({"type": "text", "text": t,
                                                 "marks": [{"type": "underline"}]})
                    elif cname == "a":
                        href = (child.get("href") or "").strip()
                        label = child.get_text(strip=True) or href
                        if href:
                            local_inline.append({"type": "text", "text": label,
                                                 "marks": [{"type": "link", "attrs": {"href": href}}]})
                        elif label:
                            local_inline.append({"type": "text", "text": label})
                    elif cname == "span":
                        style = (child.get("style") or "").lower()
                        is_mono = any(k in style for k in ("monospace", "courier", "consolas"))
                        if is_mono:
                            # Flush paragraph so far, emit code block, continue
                            if local_inline:
                                adf_content.append({"type": "paragraph", "content": local_inline.copy()})
                                local_inline.clear()
                            raw = child.get_text().replace("\xa0", " ").strip()
                            if raw:
                                adf_content.append({
                                    "type": "codeBlock",
                                    "attrs": {"language": ""},
                                    "content": [{"type": "text", "text": raw}]
                                })
                        else:
                            t = child.get_text()
                            if t.strip():
                                local_inline.append({"type": "text", "text": t})
                    elif cname == "img":
                        src = (child.get("src") or "").strip()
                        if local_inline:
                            adf_content.append({"type": "paragraph", "content": local_inline.copy()})
                            local_inline.clear()
                        if src and ATTACH_URL_SUBSTR in src:
                            lf = download_images_to_ado_attachments(src, wi_id=wi_id, issue_key=issue_key)
                            if lf:
                                up = jira_upload_attachment(issue_key, lf, wi_id=wi_id)
                                if up and up.get("id"):
                                    adf_content.append({
                                        "type": "mediaSingle",
                                        "content": [{"type": "media", "attrs": {
                                            "type": "external",
                                            "url": f"{JIRA_URL}/rest/api/2/attachment/content/{up['id']}",
                                            "width": 710, "height": 163
                                        }}]
                                    })
                        elif src:
                            local_inline.append({"type": "text", "text": src,
                                                 "marks": [{"type": "link", "attrs": {"href": src}}]})
                    else:
                        t = child.get_text()
                        if t.strip():
                            local_inline.append({"type": "text", "text": t})
            if local_inline:
                adf_content.append({"type": "paragraph", "content": local_inline})
            return

        if name in ("h1", "h2", "h3", "h4", "h5", "h6"):
            flush_inline()
            level = int(name[1])
            text = node.get_text(strip=True)
            if text:
                adf_content.append({
                    "type": "heading",
                    "attrs": {"level": level},
                    "content": [{"type": "text", "text": text}]
                })
            return

        if name in ("ul", "ol"):
            flush_inline()
            list_type = "bulletList" if name == "ul" else "orderedList"

            def collect_list_items(list_node):
                items = []
                for child in list_node.children:
                    if isinstance(child, Tag):
                        cname = (child.name or "").lower()
                        if cname == "li":
                            t = child.get_text(strip=True)
                            if t:
                                items.append({
                                    "type": "listItem",
                                    "content": [{"type": "paragraph",
                                                 "content": [{"type": "text", "text": t}]}]
                                })
                        elif cname in ("ul", "ol"):
                            # Recurse into nested list wrapper like <ul><ol><li>
                            items.extend(collect_list_items(child))
                return items

            items = collect_list_items(node)
            if items:
                adf_content.append({"type": list_type, "content": items})
            return

        # ---- DIV — recurse into children (divs are generic containers) ----
        if name == "div":
            # Check if the div itself is a code-style block
            style = (node.get("style") or "").lower()
            is_mono = any(k in style for k in ("monospace", "courier", "consolas"))
            if is_mono:
                flush_inline()
                raw = node.get_text().replace("\xa0", " ").strip()
                if raw:
                    adf_content.append({
                        "type": "codeBlock",
                        "attrs": {"language": ""},
                        "content": [{"type": "text", "text": raw}]
                    })
                return
            flush_inline()
            for child in node.children:
                walk(child)
            flush_inline()
            return

        # ---- Everything else — recurse ----
        for child in node.children:
            walk(child)

    # Walk all top-level nodes
    for top in soup.contents:
        walk(top)

    # Flush any remaining inline content
    flush_inline()

    if not adf_content:
        adf_content = [{"type": "paragraph", "content": []}]

    return {"type": "doc", "version": 1, "content": adf_content}

# ============================================================================
# END OF TABLE CONVERSION FUNCTIONS
# ============================================================================


def process_description_to_adf(issue_key: str, raw_html: str, wi_id=None) -> dict:
    if not raw_html:
        return {"type": "doc", "version": 1, "content": []}
    soup = BeautifulSoup(raw_html, "html.parser")
    adf_content = []
    seen_links: set = set()
    block_tags = {"p", "div", "li", "blockquote", "h1", "h2", "h3", "h4", "h5", "h6"}

    def flush_paragraph(inline_nodes):
        if inline_nodes:
            adf_content.append({"type": "paragraph", "content": inline_nodes.copy()})
            inline_nodes.clear()

    def make_text_node(text: str) -> dict:
        return {"type": "text", "text": text}

    def make_link_node(text: str, href: str) -> dict:
        return {"type": "text", "text": text, "marks": [{"type": "link", "attrs": {"href": href}}]}

    def handle_image_tag(img_tag):
        src = img_tag.get("src") or ""
        if src and ATTACH_URL_SUBSTR in src:
            local_file = download_images_to_ado_attachments(src, wi_id=wi_id, issue_key=issue_key)
            if not local_file:
                return
            upload = jira_upload_attachment(issue_key, local_file, wi_id=wi_id)
            if upload and upload.get("id"):
                adf_content.append({
                    "type": "mediaSingle",
                    "content": [{"type": "media", "attrs": {
                        "type": "external",
                        "url": f"{JIRA_URL}/rest/api/2/attachment/content/{upload['id']}",
                        "width": 710, "height": 163
                    }}]
                })
            elif upload and upload.get("content"):
                adf_content.append({"type": "paragraph", "content": [{
                    "type": "text", "text": upload.get("filename") or "Attachment",
                    "marks": [{"type": "link", "attrs": {"href": upload["content"]}}]
                }]})
        elif src:
            adf_content.append({"type": "paragraph", "content": [{
                "type": "text", "text": src,
                "marks": [{"type": "link", "attrs": {"href": src}}]
            }]})

    def process_nodes(nodes, inline_acc):
        from bs4 import NavigableString, Tag
        for node in nodes:
            if isinstance(node, NavigableString):
                text = str(node).replace("\r", "").replace("\n", " ").strip()
                if text:
                    inline_acc.append(make_text_node(text))
                continue
            if not isinstance(node, Tag):
                continue
            name = node.name.lower()
            if name == "br":
                inline_acc.append(make_text_node("\n"))
                continue
            if name == "img":
                if inline_acc:
                    flush_paragraph(inline_acc)
                handle_image_tag(node)
                continue
            if name == "a":
                href = (node.get("href") or "").strip()
                label = node.get_text(strip=True) or href
                if href:
                    if href in seen_links:
                        inline_acc.append(make_text_node(label))
                    else:
                        seen_links.add(href)
                        inline_acc.append(make_link_node(label, href))
                else:
                    inline_acc.append(make_text_node(label))
                continue
            if name in block_tags:
                if inline_acc:
                    flush_paragraph(inline_acc)
                local_inline = []
                process_nodes(node.children, local_inline)
                if local_inline:
                    flush_paragraph(local_inline)
                continue
            process_nodes(node.children, inline_acc)

    inline_nodes = []
    process_nodes(soup.contents, inline_nodes)
    if inline_nodes:
        flush_paragraph(inline_nodes)

    if not adf_content:
        import html as html_lib
        fallback_text = re.sub(r"<[^>]+>", " ", raw_html)
        fallback_text = html_lib.unescape(fallback_text).strip()
        if fallback_text:
            adf_content = [{"type": "paragraph", "content": [make_text_node(fallback_text)]}]

    return {"type": "doc", "version": 1, "content": adf_content}


def process_description_with_attachments(issue_key: str, raw_html: str, wi_id=None) -> Dict:
    if not raw_html:
        return to_adf_doc("")
    soup = BeautifulSoup(raw_html, "html.parser")
    for img in soup.find_all("img"):
        src = img.get("src")
        if src and ATTACH_URL_SUBSTR in src:
            filename = parse_qs(urlparse(src).query or "").get("fileName", ["embedded.png"])[0]
            local_file = download_images_to_ado_attachments(src, wi_id=wi_id, issue_key=issue_key)
            content_url = jira_upload_attachment(issue_key, local_file, wi_id=wi_id)
            if content_url:
                img.replace_with(f"!{filename}!")
    for a in soup.find_all("a"):
        href = a.get("href", "").strip()
        text = a.get_text(strip=True) or href
        a.replace_with(f"[{text}|{href}]")
    clean_text = soup.get_text("\n").strip()
    return to_adf_doc(clean_text)


def clean_html_steps(html_text):
    if not html_text:
        return ""
    return BeautifulSoup(html_text, "html.parser").get_text(separator=" ", strip=True)


def steps_formatter(xml_data):
    global steps_payload
    print(xml_data)
    if not xml_data or not xml_data.strip():
        return {}
    root = ET.fromstring(xml_data)
    seen_steps = set()
    step_no = 0
    jira_payload = {
        "fields": {
            "customfield_10632": {
                "type": "doc", "version": 1,
                "content": [{"type": "table",
                              "attrs": {"isNumberColumnEnabled": False, "layout": "default"},
                              "content": [{"type": "tableRow", "content": [
                                  {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Steps", "marks": [{"type": "strong"}]}]}]},
                                  {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Action", "marks": [{"type": "strong"}]}]}]},
                                  {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Expected result", "marks": [{"type": "strong"}]}]}]},
                                  {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Attachments", "marks": [{"type": "strong"}]}]}]},
                              ]}]}
                ]
            }
        }
    }
    table_content = jira_payload["fields"]["customfield_10632"]["content"][0]["content"]
    steps_sorted = sorted(root.findall(".//step[@type]"), key=lambda x: int(x.get("id", 0)))
    for step in steps_sorted:
        step_type = step.get("type")
        ps_list = step.findall("parameterizedString")
        action_text = ""
        expected_text = ""
        if step_type == "ActionStep":
            action_text = " ".join(clean_html_steps(p.text) for p in ps_list if p.text)
            expected_text = " "
        elif step_type == "ValidateStep":
            if len(ps_list) >= 2:
                action_text = clean_html_steps(ps_list[0].text)
                expected_text = clean_html_steps(ps_list[1].text)
        step_key = f"{step_type}-{action_text}-{expected_text}"
        if not action_text and not expected_text:
            continue
        if step_key in seen_steps:
            continue
        seen_steps.add(step_key)
        step_no += 1
        table_content.append({
            "type": "tableRow", "content": [
                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": str(step_no)}]}]},
                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": action_text}]}]},
                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": expected_text or ' '}]}]},
                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": " "}]}]},
            ]
        })
    steps_payload = json.dumps(jira_payload, indent=2)
    return steps_payload

# ============================================================
# FIX RELATIVE URLS IN REPRO STEPS
# ============================================================

def fix_relative_urls_in_repro_steps(repro_html: str) -> str:
    """Convert relative URLs to absolute URLs in ReproSteps HTML"""
    
    if not repro_html:
        return repro_html
    
    pattern = r'((?:src|href)=")(/HESource/[^"]*)'
    
    def replace_url(match):
        attr_part = match.group(1)
        relative_url = match.group(2)
        absolute_url = f"https://dev.azure.com{relative_url}"
        return attr_part + absolute_url
    
    fixed_html = re.sub(pattern, replace_url, repro_html)
    return fixed_html

def download_and_upload_reprosteps_images(issue_key: str, repro_html: str, wi_id=None) -> Dict[str, str]:
    attachment_map = {}
    if not repro_html:
        return attachment_map
    soup = BeautifulSoup(repro_html, "html.parser")
    for img in soup.find_all("img"):
        src = img.get("src")
        if not src or src in attachment_map:
            continue

        if ATTACH_URL_SUBSTR in src:
            # Existing ADO attachment handling
            filename = parse_qs(urlparse(src).query or "").get("fileName", ["attachment.png"])[0]
            local_file = ado_download_attachment(src, filename, wi_id=wi_id, issue_key=issue_key)
        else:
            # NEW: Handle external image URLs (e.g. tpondemand.com, etc.)
            try:
                parsed = urlparse(src)
                filename = os.path.basename(parsed.path) or f"external_image_{len(attachment_map)}.png"
                filename = sanitize_filename(filename)
                if not os.path.splitext(filename)[1]:
                    filename += ".png"
                ensure_dir(ATTACH_DIR)
                local_path = unique_path(ATTACH_DIR, filename)
                log(f"   📥 Downloading external image: {src}")
                r = requests.get(src, timeout=15, stream=True)
                if r.status_code == 200:
                    with open(local_path, "wb") as f:
                        for chunk in r.iter_content(8192):
                            if chunk:
                                f.write(chunk)
                    local_file = local_path
                    log(f"   ✅ Downloaded external image: {filename}")
                else:
                    log(f"   ⚠️ Failed to download external image ({r.status_code}): {src}")
                    local_file = None
            except Exception as e:
                log(f"   ⚠️ Error downloading external image {src}: {e}")
                local_file = None

        if not local_file:
            continue
        upload_info = jira_upload_attachment(issue_key, local_file, wi_id=wi_id)
        if upload_info and upload_info.get("id"):
            attachment_map[src] = upload_info["id"]
        try:
            if local_file and os.path.exists(local_file):
                os.remove(local_file)
        except Exception:
            pass

    return attachment_map

# ============================================================
# IMPROVED convert_ado_reprosteps_to_jira_adf FUNCTION
# ============================================================

def convert_ado_reprosteps_to_jira_adf(html_input: str, attachment_map: Dict[str, str] = None, issue_key: str = None) -> Dict:
    """
    Convert ADO ReproSteps HTML to Jira ADF, preserving document order.
    Handles: tables, ordered/unordered lists, paragraphs, divs, images, code blocks.
    """
    if not html_input:
        return {"type": "doc", "version": 1, "content": []}

    soup = BeautifulSoup(html_input, "html.parser")
    attachment_map = attachment_map or {}
    doc_content: List = []

    def make_media_node(src: str):
        """Create media node with proper URL formatting."""
        if src in attachment_map:
            base = clean_base(JIRA_URL)
            url = f"{base}/rest/api/3/attachment/content/{attachment_map[src]}"
            return {"type": "mediaSingle", "attrs": {"layout": "center"},
                    "content": [{"type": "media", "attrs": {"type": "external", "url": url}}]}
        return {"type": "mediaSingle", "attrs": {"layout": "center"},
                "content": [{"type": "media", "attrs": {"type": "external", "url": src}}]}

    def _is_code_block_div(element) -> bool:
        """Check if a div should be treated as a code block."""
        if element.name != "div":
            return False
        style = (element.get("style") or "").lower()
        if "monospace" in style or "courier" in style or "consolas" in style:
            return True
        if "#3b3b3b" in style or "3b3b3b" in style:
            return True
        return False

    def inline_nodes_from(element) -> List:
        """Extract inline ADF nodes from an element."""
        nodes = []

        for child in element.children:
            if isinstance(child, NavigableString):
                text = html.unescape(str(child))
                text = text.replace("\xa0", " ")
                if text.strip():
                    nodes.append({"type": "text", "text": text})
            elif isinstance(child, NavigableString.__class__.__bases__[0]):
                name = (child.name or "").lower() if hasattr(child, 'name') else ""

                if name in ("b", "strong"):
                    text = child.get_text()
                    if text.strip():
                        nodes.append({
                            "type": "text",
                            "text": text,
                            "marks": [{"type": "strong"}]
                        })

                elif name in ("i", "em"):
                    text = child.get_text()
                    if text.strip():
                        nodes.append({
                            "type": "text",
                            "text": text,
                            "marks": [{"type": "em"}]
                        })

                elif name == "code":
                    text = child.get_text()
                    if text.strip():
                        nodes.append({
                            "type": "text",
                            "text": text,
                            "marks": [{"type": "code"}]
                        })

                elif name == "a":
                    href = (child.get("href") or "").strip()
                    label = child.get_text(strip=True) or href
                    if href:
                        nodes.append({
                            "type": "text",
                            "text": label,
                            "marks": [{"type": "link", "attrs": {"href": href}}]
                        })
                    elif label:
                        nodes.append({"type": "text", "text": label})

                elif name == "br":
                    nodes.append({"type": "hardBreak"})

                elif name == "span":
                    nodes.extend(inline_nodes_from(child))

                elif name == "img":
                    pass

                else:
                    nodes.extend(inline_nodes_from(child))

        return nodes

    def walk(node):
        """Walk DOM nodes and emit ADF block content."""
        if isinstance(node, NavigableString):
            text = html.unescape(str(node)).replace("\xa0", " ").strip()
            if text:
                doc_content.append({
                    "type": "paragraph",
                    "content": [{"type": "text", "text": text}]
                })
            return

        if not hasattr(node, 'name'):
            return

        name = (node.name or "").lower()

        if name == "img":
            src = (node.get("src") or "").strip() if hasattr(node, 'get') else ""
            if src:
                doc_content.append(make_media_node(src))
            return

        if name == "ul":
            items = []
            for li in node.find_all("li", recursive=False) if hasattr(node, 'find_all') else []:
                inline = inline_nodes_from(li)
                if inline:
                    items.append({
                        "type": "listItem",
                        "content": [{"type": "paragraph", "content": inline}]
                    })

            if items:
                doc_content.append({
                    "type": "bulletList",
                    "content": items
                })
            return

        if name == "ol":
            items = []
            for li in node.find_all("li", recursive=False) if hasattr(node, 'find_all') else []:
                inline = inline_nodes_from(li)
                if inline:
                    items.append({
                        "type": "listItem",
                        "content": [{"type": "paragraph", "content": inline}]
                    })

            if items:
                doc_content.append({
                    "type": "orderedList",
                    "content": items
                })
            return

        if name in ("h1", "h2", "h3", "h4", "h5", "h6"):
            level = int(name[1])
            inline = inline_nodes_from(node)
            if inline:
                doc_content.append({
                    "type": "heading",
                    "attrs": {"level": level},
                    "content": inline
                })
            return

        if name == "table":
            rows = []
            for tr in node.find_all("tr") if hasattr(node, 'find_all') else []:
                cells = []
                for td in tr.find_all(["td", "th"]) if hasattr(tr, 'find_all') else []:
                    cell_blocks = []
                    for img in td.find_all("img") if hasattr(td, 'find_all') else []:
                        src = (img.get("src") or "").strip() if hasattr(img, 'get') else ""
                        if src:
                            cell_blocks.append(make_media_node(src))
                        if hasattr(img, 'decompose'):
                            img.decompose()

                    inline = inline_nodes_from(td)
                    if inline:
                        cell_blocks.append({"type": "paragraph", "content": inline})
                    if not cell_blocks:
                        cell_blocks = [{"type": "paragraph", "content": []}]

                    cell_type = "tableHeader" if td.name == "th" else "tableCell"
                    cells.append({"type": cell_type, "content": cell_blocks})

                if cells:
                    rows.append({"type": "tableRow", "content": cells})

            if rows:
                doc_content.append({
                    "type": "table",
                    "attrs": {"isNumberColumnEnabled": False, "layout": "default"},
                    "content": rows
                })
            return

        if name == "pre" or _is_code_block_div(node):
            raw = node.get_text() if hasattr(node, 'get_text') else str(node)
            raw = raw.replace("\xa0", " ").strip()
            if raw:
                doc_content.append({
                    "type": "codeBlock",
                    "attrs": {"language": "json"},
                    "content": [{"type": "text", "text": raw}]
                })
            return

        if name == "p":
            for img in node.find_all("img") if hasattr(node, 'find_all') else []:
                src = (img.get("src") or "").strip() if hasattr(img, 'get') else ""
                if src:
                    doc_content.append(make_media_node(src))
                if hasattr(img, 'decompose'):
                    img.decompose()

            inline = inline_nodes_from(node)
            if inline:
                doc_content.append({
                    "type": "paragraph",
                    "content": inline
                })
            return

        if name in ("div", "section", "article", "blockquote"):
            for child in node.children if hasattr(node, 'children') else []:
                walk(child)
            return

        for child in node.children if hasattr(node, 'children') else []:
            walk(child)

    for top in soup.contents:
        walk(top)

    if not doc_content:
        doc_content = [{"type": "paragraph", "content": []}]

    return {"type": "doc", "version": 1, "content": doc_content}


def build_jira_fields_from_ado(wi: Dict) -> Dict:
    global steps_payload
    steps_payload = None
    f = wi.get("fields", {})
    wi_id = wi.get("id")
    steps = f.get("Microsoft.VSTS.TCM.Steps", " ")
    if steps:
        try:
            steps_payload = steps_formatter(steps)
            log_to_excel(wi_id, None, "Steps Parsing", "Success", "Parsed test steps")
        except Exception as e:
            log_to_excel(wi_id, None, "Steps Parsing", "Failed", str(e)[:100])

     # ============================================================
    # SUMMARY - Clean newlines FIRST
    # ============================================================
    summary = f.get("System.Title", "No Title")
    # STEP 1: Remove newlines (\r\n, \n, \r)
    summary = re.sub(r'[\r\n]+', ' ', summary).strip()
    # STEP 2: Collapse multiple spaces
    summary = re.sub(r'\s{2,}', ' ', summary)
    # STEP 3: Ensure not empty
    if not summary:
        summary = "No Title"

    # STEP 4: Track truncation
    full_summary = summary
    summary_was_truncated = False
    max_summary_length = 255

    if len(summary) > max_summary_length:
        summary_was_truncated = True
        original_length = len(summary)
        summary = summary[:max_summary_length]
        log_to_excel(wi_id, None, "Summary Truncation", "Warning",
                     f"Truncated from {original_length} to 255 chars. Full text will be in description.")

    # STEP 5: Get description
    raw_desc = f.get("System.Description", "")

    # STEP 6: Prepend full summary if truncated
    if summary_was_truncated:
        full_summary_text = f"*Full Summary :*\n\n{full_summary}\n\n"
        raw_desc = full_summary_text + (raw_desc or "")

    ado_type = f.get("System.WorkItemType", "Defect")
    jira_issuetype = WORKITEM_TYPE_MAP.get(ado_type, "Defect")
    log_to_excel(wi_id, None, "Issue Type", "Success", f"ADO: {ado_type} → Jira: {jira_issuetype}")

    tags = f.get("System.Tags", "")
    labels: List[str] = []
    if tags:
        parts = re.split(r"[;,]", tags)
        labels = [p.strip().replace(" ", "-") for p in parts if p.strip()]
        log_to_excel(wi_id, None, "Tags", "Success", f"Found {len(labels)} labels")

    assignee_email = None
    assigned_to = f.get("System.AssignedTo")
    if isinstance(assigned_to, dict):
        assignee_email = assigned_to.get("uniqueName") or assigned_to.get("mail")

    ado_state = f.get("System.State", "New")

    fields: Dict = {
        "project": {"key": JIRA_PROJECT_KEY},
        "summary": summary,
        "issuetype": {"name": jira_issuetype},
        "description": to_adf_doc(" "),
        "labels": labels,
    }

    # Created Date
    created_date = f.get("System.CreatedDate")
    if created_date:
        try:
            fields["customfield_12527"] = convert_ado_datetime(created_date)
            log_to_excel(wi_id, None, "Created Date", "Success", f"Date: {created_date[:10]}")
        except Exception as e:
            log_to_excel(wi_id, None, "Created Date", "Failed", str(e)[:100])

    # Due Date
    target_date = f.get("Microsoft.VSTS.Scheduling.TargetDate")
    if target_date:
        try:
            fields["duedate"] = convert_ado_datetime(target_date)
            log_to_excel(wi_id, None, "Due Date", "Success", f"Date: {target_date[:10]}")
        except Exception as e:
            log_to_excel(wi_id, None, "Due Date", "Failed", str(e)[:100])

    # Use simplified approach - just add to build_jira_fields_from_ado()
    # proposed_fix = f.get("Microsoft.VSTS.CMMI.ProposedFix")
    # if proposed_fix:
    #     clean_html_val = clean_html_to_text(proposed_fix)
    #     fields["customfield_12787"] = to_adf_doc(clean_html_val)
    #     log_to_excel(wi_id, None, "Proposed Fix", "Success", f"Length: {len(clean_html_val)}")

    # Priority Rank
    priority_rank = f.get("Custom.PriorityRank")
    if priority_rank is not None:
        try:
            fields["customfield_11700"] = float(priority_rank)
            log_to_excel(wi_id, None, "Priority Rank", "Success", f"Value: {priority_rank}")
        except ValueError as e:
            log_to_excel(wi_id, None, "Priority Rank", "Failed", str(e)[:100])

    # Blocking Type
    blocking_type = f.get("Custom.BlockingType")
    if blocking_type:
        fields["customfield_11699"] = {"value": blocking_type}
        log_to_excel(wi_id, None, "Blocking Type", "Success", blocking_type)

    # Bug Severity
    bug_severity = f.get("Custom.BugSeverity")
    if bug_severity:
        fields["customfield_10090"] = {"value": bug_severity}
        log_to_excel(wi_id, None, "Bug Severity", "Success", bug_severity)

    # Bug Priority
    bug_priority = f.get("Custom.BugPriority")
    if bug_priority:
        match = re.match(r"(P\d+)", bug_priority)
        if match:
            mapped = BUG_PRIORITY_MAP.get(match.group(1))
            if mapped:
                fields["priority"] = {"name": mapped}
                log_to_excel(wi_id, None, "Bug Priority", "Success", f"{bug_priority} → {mapped}")
            else:
                log_to_excel(wi_id, None, "Bug Priority", "Warning", f"{bug_priority} not mapped")

    # Deployment Type
    deployment_type = f.get("Custom.DeploymentType")
    if deployment_type:
        deployment_type = deployment_type.strip()  # remove extra spaces
        fields["customfield_12137"] = {"value": deployment_type}
        log_to_excel(wi_id, None, "DeploymentType", "Success", deployment_type)

    # Found In (URL / Text field)
    found_in = f.get("Microsoft.VSTS.Build.FoundIn")
    if found_in:
        fields["customfield_12668"] = found_in
        log_to_excel(wi_id, None, "FoundIn", "Success", found_in)

    # Found by Automation
    found_by_automation = f.get("Custom.FoundbyAutomation")
    if found_by_automation:
        fields["customfield_11706"] = {"value": found_by_automation}
        log_to_excel(wi_id, None, "Found by Automation", "Success", found_by_automation)

    # Resolution
    resolved_reason = f.get("Microsoft.VSTS.Common.ResolvedReason")
    if resolved_reason:
        jira_resolution = RESOLUTION_MAP.get(resolved_reason)
        if jira_resolution:
            fields["resolution"] = {"name": jira_resolution}
            log_to_excel(wi_id, None, "Resolution", "Success", f"{resolved_reason} → {jira_resolution}")
        else:
            log_to_excel(wi_id, None, "Resolution", "Warning", f"{resolved_reason} not mapped")

    # Release Notes Status
    release_notes_status = f.get("Custom.ReleaseNotesStatus")
    if release_notes_status:
        fields["customfield_11701"] = {"value": release_notes_status}
        log_to_excel(wi_id, None, "Release Notes Status", "Success", release_notes_status)

    # Value Stream
    value_stream = f.get("Custom.ValueStream")
    if value_stream:
        fields["customfield_11702"] = {"value": value_stream}
        log_to_excel(wi_id, None, "Value Stream", "Success", value_stream)

    # Customer Name
    customer_name = f.get("Custom.CustomerName")
    if customer_name:
        parts = [c.strip() for c in customer_name.split(";") if c.strip()]
        fields["customfield_12350"] = [{"value": p} for p in parts]
        log_to_excel(wi_id, None, "Customer Name", "Success", f"Found {len(parts)} customers")

    # Provider Type
    provider_type = f.get("Custom.ProviderType")
    if provider_type:
        parts = [p.strip() for p in provider_type.split(";") if p.strip()]
        fields["customfield_12383"] = [{"value": p} for p in parts]
        log_to_excel(wi_id, None, "Provider Type", "Success", f"Found {len(parts)} types")

    # Product
    product = f.get("Custom.Product")
    if product:
        fields["customfield_11703"] = {"value": product}
        log_to_excel(wi_id, None, "Product", "Success", product)

    # Bug Area
    bug_area = f.get("Custom.BugArea")
    if bug_area:
        fields["customfield_11704"] = {"value": bug_area}
        log_to_excel(wi_id, None, "Bug Area", "Success", bug_area)

    # Bug Type
    bug_type = f.get("Custom.BugType")
    if bug_type:
        fields["customfield_11705"] = {"value": bug_type}
        log_to_excel(wi_id, None, "Bug Type", "Success", bug_type)

    # Deliverable Type
    deliverable_type = f.get("Custom.DeliverableType")
    if deliverable_type:
        fields["customfield_11707"] = {"value": deliverable_type}
        log_to_excel(wi_id, None, "Deliverable Type", "Success", deliverable_type)

    # Risk Opened
    risk_opened = f.get("Custom.RiskOpened")
    if risk_opened is not None:
        mapped_value = "True" if risk_opened else "False"
        fields["customfield_11708"] = {"value": mapped_value}

    # Custom Status
    custom_status = f.get("Custom.Status")
    if custom_status:
        try:
            fields["customfield_11794"] = {"value": custom_status}
            log_to_excel(wi_id, None, "Custom Status", "Success", f"Value: {custom_status}")
        except Exception as e:
            log_to_excel(wi_id, None, "Custom Status", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Custom Status", "Skipped", "No custom status in ADO")

    # Client Requests RCA (Boolean → Single Select)
    client_requests_rca = f.get("Custom.ClientRequestsRCA")
    if client_requests_rca is not None:
        value_str = "True" if client_requests_rca else "False"
        fields["customfield_12669"] = {"value": value_str}
        log_to_excel(wi_id, None, "ClientRequestsRCA", "Success", value_str)

    # Automation (Single Select)
    automation = f.get("Custom.Automation")
    if automation:
        fields["customfield_12670"] = {"value": automation}
        log_to_excel(wi_id, None, "Automation", "Success", automation)

    # Dollar Amount (Text Field)
    dollar_amount = f.get("Custom.DollarAmount")
    if dollar_amount:
        fields["customfield_12671"] = dollar_amount
        log_to_excel(wi_id, None, "DollarAmount", "Success", dollar_amount)

    # Number of Claims (Text Field)
    number_of_claims = f.get("Custom.NumberofClaims")
    if number_of_claims:
        fields["customfield_12704"] = str(number_of_claims)
        log_to_excel(wi_id, None, "NumberofClaims", "Success", number_of_claims)

    # Client Scope (Single Select)
    client_scope = f.get("Custom.ClientScope")
    if client_scope:
        fields["customfield_12461"] = {"value": client_scope}
        log_to_excel(wi_id, None, "Client Scope", "Success", client_scope)

    # Issues Log (Single Select)
    issues_log = f.get("Custom.IssuesLog")
    if issues_log:
        fields["customfield_12705"] = {"value": issues_log}
        log_to_excel(wi_id, None, "IssuesLog", "Success", issues_log)

    # Origin Ticket ID
    origin_ticket_id = f.get("Custom.OriginTicketID")
    if origin_ticket_id:
        fields["customfield_12871"] = str(origin_ticket_id)
        log_to_excel(wi_id, None, "Origin Ticket ID", "Success", origin_ticket_id)

    # Date Reported
    date_reported = f.get("Custom.DateReported")
    if date_reported:
        try:
            fields["customfield_12872"] = convert_ado_datetime(date_reported)
            log_to_excel(wi_id, None, "Date Reported", "Success", f"Date: {date_reported[:10]}")
        except Exception as e:
            log_to_excel(wi_id, None, "Date Reported", "Failed", str(e)[:100])

    # Origin Ticket Assigned To
    origin_ticket_assigned = f.get("Custom.OriginTicketAssignedTo")
    if origin_ticket_assigned:
        origin_email = None

        if isinstance(origin_ticket_assigned, dict):
            origin_email = origin_ticket_assigned.get("uniqueName") or origin_ticket_assigned.get("mail")
        elif isinstance(origin_ticket_assigned, str):
            origin_email = origin_ticket_assigned

        if origin_email:
            origin_account_id = get_jira_account_id_for_email(origin_email)

            if origin_account_id:
                fields["customfield_12873"] = {"id": origin_account_id}
                log_to_excel(wi_id, None, "Origin Ticket Assigned To", "Success", origin_email)
            else:
                log_to_excel(wi_id, None, "Origin Ticket Assigned To", "Failed", f"No mapping for: {origin_email}")

    # Client Priority Level
    client_priority = f.get("Custom.ClientPriorityLevel")
    if client_priority:
        fields["customfield_12874"] = {"value": client_priority}
        log_to_excel(wi_id, None, "Client Priority Level", "Success", client_priority)

    # Cycle Time Start Date (Date Picker)
    cycle_time_start = f.get("Custom.CycleTimeStartDate")
    if cycle_time_start:
        formatted = convert_ado_datetime(cycle_time_start)
        if formatted:
            fields["customfield_12708"] = formatted[:10]  # Only YYYY-MM-DD
            log_to_excel(wi_id, None, "CycleTimeStartDate", "Success", formatted[:10])

    # Dev Delivery ETA (Date Time Picker)
    dev_delivery_eta = f.get("Custom.DevDeliveryETA")
    if dev_delivery_eta:
        formatted = convert_ado_datetime(dev_delivery_eta)
        if formatted:
            fields["customfield_12709"] = formatted
            log_to_excel(wi_id, None, "DevDeliveryETA", "Success", formatted)

    # Delivery Actual Date (Date Picker)
    delivery_actual = f.get("Custom.DeliveryActualDate")
    if delivery_actual:
        formatted = convert_ado_datetime(delivery_actual)
        if formatted:
            fields["customfield_12142"] = formatted[:10]  # Only date part
            log_to_excel(wi_id, None, "DeliveryActualDate", "Success", formatted[:10])

    # QA Delivery ETA (Date Picker)
    qa_delivery_eta = f.get("Custom.QADeliveryETA")
    if qa_delivery_eta:
        formatted = convert_ado_datetime(qa_delivery_eta)
        if formatted:
            fields["customfield_12710"] = formatted[:10]  # Extract date only
            log_to_excel(wi_id, None, "QADeliveryETA", "Success", formatted[:10])

    # QA Test Complete Date (Date Picker)
    qa_test_complete = f.get("Custom.QATestCompleteDate")
    if qa_test_complete:
        formatted = convert_ado_datetime(qa_test_complete)
        if formatted:
            fields["customfield_12134"] = formatted[:10]  # Extract YYYY-MM-DD
            log_to_excel(wi_id, None, "QATestCompleteDate", "Success", formatted[:10])

    # Branch Name
    branch_name = f.get("Custom.BranchName")
    if branch_name:
        fields["customfield_11710"] = str(branch_name)
        log_to_excel(wi_id, None, "Branch Name", "Success", branch_name)

    # Environment Found In
    environment = f.get("Custom.EnvironmentFoundIn")
    if environment:
        parts = [e.strip().strip('"') for e in environment.split(";") if e.strip()]
        fields["customfield_12597"] = [{"value": p} for p in parts]
        log_to_excel(wi_id, None, "Environment", "Success", f"Found {len(parts)} environments")

    # Hotfix Production Date
    hotfix_production_date = f.get("Custom.HotfixProductionDate")
    if hotfix_production_date:
        try:
            fields["customfield_12416"] = convert_ado_datetime(hotfix_production_date)
            log_to_excel(wi_id, None, "Hotfix Production Date", "Success", hotfix_production_date[:10])
        except Exception as e:
            log_to_excel(wi_id, None, "Hotfix Production Date", "Failed", str(e)[:100])

    # Release
    release_val = f.get("Custom.Release")
    if release_val:
        fields["customfield_11712"] = {"value": release_val}
        log_to_excel(wi_id, None, "Release", "Success", release_val)

    # Bug Failure Analysis
    bug_failure_val = f.get("Custom.BugFailureAnalysis")
    if bug_failure_val:
        fields["customfield_12820"] = {"value": bug_failure_val}
        log_to_excel(wi_id, None, "Bug Failure Analysis", "Success", bug_failure_val)

    # Bug User Analysis Subcategory
    bug_user_analysis_subcat = f.get("Custom.BugUserAnalysisSubcategory")
    if bug_user_analysis_subcat:
        fields["customfield_12821"] = {"value": bug_user_analysis_subcat}
        log_to_excel(wi_id, None, "Bug User Analysis Subcategory", "Success", bug_user_analysis_subcat)

    # QA Bug User Analysis Subcategory
    qa_bug_user_analysis_subcat = f.get("Custom.QABugUserAnalysisSubcategory")
    if qa_bug_user_analysis_subcat:
        fields["customfield_12822"] = {"value": qa_bug_user_analysis_subcat}
        log_to_excel(wi_id, None, "QA Bug User Analysis Subcategory", "Success", qa_bug_user_analysis_subcat)

    # Related User Story where Defect was Introduced
    related_user_story = f.get("Custom.RelatedUserStorywhereDefectwasIntroduced")
    if related_user_story:
        fields["customfield_12823"] = {"value": related_user_story}
        log_to_excel(wi_id, None, "Related User Story where Defect was Introduced", "Success", related_user_story)

    # Team the bug is associated with
    team_bug_assoc = f.get("Custom.Teamthebugisassociatedwith")
    if team_bug_assoc:
        fields["customfield_12824"] = {"value": team_bug_assoc}
        log_to_excel(wi_id, None, "Team the bug is associated with", "Success", team_bug_assoc)

    # Developer who Introduced Defect
    developer_defect = f.get("Custom.DeveloperwhoIntroducedDefect")
    if developer_defect:
        fields["customfield_12825"] = str(developer_defect)
        log_to_excel(wi_id, None, "Developer who Introduced Defect", "Success", developer_defect)

    # QA who originally tested introduced Defect
    qa_original_tester = f.get("Custom.QAwhooriginallytestedintroducedDefect")
    if qa_original_tester:
        qa_email = None

        if isinstance(qa_original_tester, dict):
            qa_email = qa_original_tester.get("uniqueName") or qa_original_tester.get("mail")

        elif isinstance(qa_original_tester, str):
            qa_email = qa_original_tester

        if qa_email:
            qa_account_id = get_jira_account_id_for_email(qa_email)

            if qa_account_id:
                fields["customfield_12826"] = {"id": qa_account_id}
                log_to_excel(wi_id, None, "QA who originally tested introduced Defect", "Success", qa_email)
            else:
                log_to_excel(wi_id, None, "QA who originally tested introduced Defect", "Warning", f"No mapping for: {qa_email}")

    # Release where Bug was introduced
    release_bug_intro = f.get("Custom.ReleasewhereBugwasintroduced")
    if release_bug_intro:
        fields["customfield_12859"] = {"value": release_bug_intro}
        log_to_excel(wi_id, None, "Release where Bug was introduced", "Success", release_bug_intro)

    # What type of defect is it
    defect_type = f.get("Custom.Whattypeofdefectisit")
    if defect_type:
        fields["customfield_12860"] = {"value": defect_type}
        log_to_excel(wi_id, None, "What type of defect is it", "Success", defect_type)

    # Is this Defect related to a testing issue
    testing_issue = f.get("Custom.IsthisDefectrelatedtoatestingissue")
    if testing_issue:
        fields["customfield_12861"] = {"value": testing_issue}
        log_to_excel(wi_id, None, "Is this Defect related to a testing issue", "Success", testing_issue)

    # QA Bug User Analysis Subcategory
    qa_bug_user_analysis = f.get("Custom.QABugUserAnalysisSubcategory")
    if qa_bug_user_analysis:
        fields["customfield_12862"] = {"value": qa_bug_user_analysis}
        log_to_excel(wi_id, None, "QA Bug User Analysis Subcategory", "Success", qa_bug_user_analysis)

    # Impacted or Affected Application by the Bug
    impacted_app = f.get("Custom.ImpactedorAffectedApplicationbytheBug")
    if impacted_app:
        fields["customfield_12863"] = {"value": impacted_app}
        log_to_excel(wi_id, None, "Impacted or Affected Application by the Bug", "Success", impacted_app)

    # QA who introduced defect
    qa_introduced_defect = f.get("Custom.QAwhointroduceddefect")
    if qa_introduced_defect:
        qa_email = None

        if isinstance(qa_introduced_defect, dict):
            qa_email = qa_introduced_defect.get("uniqueName") or qa_introduced_defect.get("mail")

        elif isinstance(qa_introduced_defect, str):
            qa_email = qa_introduced_defect

        if qa_email:
            qa_account_id = get_jira_account_id_for_email(qa_email)

            if qa_account_id:
                fields["customfield_12864"] = {"id": qa_account_id}
                log_to_excel(wi_id, None, "QA who introduced defect", "Success", qa_email)
            else:
                log_to_excel(wi_id, None, "QA who introduced defect", "Warning", f"No mapping for: {qa_email}")

    # CYPRESS
    cypress_val = f.get("Custom.CYPRESS")
    if cypress_val:
        fields["customfield_12865"] = {"value": cypress_val}
        log_to_excel(wi_id, None, "CYPRESS", "Success", cypress_val)

    # Trend Notes
    trend_notes = f.get("Custom.TrendNotes")
    if trend_notes:
        fields["customfield_12866"] = {"value": trend_notes}
        log_to_excel(wi_id, None, "Trend Notes", "Success", trend_notes)

    # CTMS
    ctms_val = f.get("Custom.CTMS")
    if ctms_val:
        fields["customfield_12867"] = {"value": ctms_val}
        log_to_excel(wi_id, None, "CTMS", "Success", ctms_val)

    # Implementation Date
    implementation_date_val = f.get("Custom.ImplementationDate")
    if implementation_date_val:
        try:
            implementation_date = convert_ado_datetime(implementation_date_val)
            if implementation_date:
                fields["customfield_11755"] = implementation_date
                log_to_excel(wi_id, None, "Implementation Date", "Success", implementation_date_val[:10])
        except Exception as e:
            log_to_excel(wi_id, None, "Implementation Date", "Failed", str(e)[:100])

    # Status Dropdown
    status_dropdown = f.get("Custom.StatusDropdown")
    if status_dropdown:
        fields["customfield_11756"] = {"value": status_dropdown}
        log_to_excel(wi_id, None, "Status Dropdown", "Success", status_dropdown)

    # CAP Author
    cap_author = f.get("Custom.CAPAuthor")
    if cap_author:
        cap_author_email = None
        if isinstance(cap_author, dict):
            cap_author_email = cap_author.get("uniqueName") or cap_author.get("mail")
        elif isinstance(cap_author, str):
            cap_author_email = cap_author
        if cap_author_email:
            cap_account_id = get_jira_account_id_for_email(cap_author_email)
            if cap_account_id:
                fields["customfield_11758"] = {"id": cap_account_id}
                log_to_excel(wi_id, None, "CAP Author", "Success", cap_author_email)
            else:
                log_to_excel(wi_id, None, "CAP Author", "Warning", f"No mapping for: {cap_author_email}")

    # Assignee
    account_id = get_jira_account_id_for_email(assignee_email)
    if account_id:
        fields["assignee"] = {"id": account_id}
        log_to_excel(wi_id, None, "Assignee", "Success", assignee_email)
    else:
        if assignee_email:
            log_to_excel(wi_id, None, "Assignee", "Warning", f"No mapping for: {assignee_email}")
        else:
            log_to_excel(wi_id, None, "Assignee", "Skipped", "No assignee in ADO")

    # Reporter
    created_by = f.get("System.CreatedBy")
    reporter_email = None
    if isinstance(created_by, dict):
        reporter_email = created_by.get("uniqueName") or created_by.get("mail")
        if reporter_email:
            reporter_email = reporter_email.lower().strip()
    if reporter_email and reporter_email in USER_MAP:
        fields["reporter"] = {"id": USER_MAP[reporter_email]}
        log_to_excel(wi_id, None, "Reporter", "Success", reporter_email)
    else:
        try:
            fields["reporter"] = {"id": JIRA_ACCOUNT_ID}
            log_to_excel(wi_id, None, "Reporter", "Success", f"Default reporter used")
        except Exception as e:
            log_to_excel(wi_id, None, "Reporter", "Failed", str(e)[:100])

    # ADO Work Item Link
    wid = f.get("System.Id")
    if wid:
        ado_base = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}"
        fields["customfield_11600"] = f"{ado_base}/_workitems/edit/{wid}"
        log_to_excel(wi_id, None, "ADO Link", "Success", f"WI: {wid}")

    # Area Path (select-list)
    area_path = f.get("System.AreaPath")
    if area_path:
        fields["customfield_12910"] = {"value": area_path}
        log_to_excel(wi_id, None, "Area Path", "Success", area_path)

    # Area Path
    area = f.get("System.AreaPath")
    if area:
        fields["customfield_11601"] = str(area)
        log_to_excel(wi_id, None, "Area Path", "Success", area)

    # Iteration Path
    iteration = f.get("System.IterationPath")
    if iteration:
        fields["customfield_11602"] = str(iteration)
        log_to_excel(wi_id, None, "Iteration Path", "Success", iteration)

    # Reason
    reason = f.get("System.Reason")
    if reason:
        fields["customfield_11603"] = str(reason)
        log_to_excel(wi_id, None, "Reason", "Success", reason)

    log_to_excel(wi_id, None, "Field Mapping", "Complete", f"Mapped {len(fields)} fields total")
    return fields


OUTPUT_DIR = "ado_attachments"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def jira_transition_issue(issue_key: str, ado_state: str, wi_id=None):
    target_status = STATE_MAP.get(ado_state)
    if not target_status:
        log_to_excel(wi_id, issue_key, "Transition", "Skipped", f"No mapping for ADO state: {ado_state}")
        return
    base = clean_base(JIRA_URL)
    url = f"{base}/rest/api/3/issue/{issue_key}/transitions"
    r = api_request("get", url, wi_id=wi_id, issue_key=issue_key,
                    step="Fetch Transitions", auth=jira_auth(),
                    headers={"Accept": "application/json"})
    if r.status_code != 200:
        log_to_excel(wi_id, issue_key, "Transition", "Failed", f"Could not fetch transitions: {r.status_code}")
        return
    transitions = r.json().get("transitions", [])
    transition_id = next((t["id"] for t in transitions if t["to"]["name"] == target_status), None)
    if not transition_id:
        log(f"⚠️ No transition found to '{target_status}' for {issue_key}")
        log_to_excel(wi_id, issue_key, "Transition", "Failed", f"No transition to {target_status}")
        return
    payload = {"transition": {"id": transition_id}}
    r = api_request("post", url, wi_id=wi_id, issue_key=issue_key,
                    step=f"Transition to {target_status}",
                    auth=jira_auth(), headers={"Content-Type": "application/json"}, json=payload)
    if r.status_code in (200, 204):
        log(f"✅ {issue_key} transitioned to '{target_status}'")
        log_to_excel(wi_id, issue_key, "Transition", "Success", f"ADO: {ado_state} → Jira: {target_status}")
    else:
        log(f"⚠️ Failed to transition {issue_key}: {r.status_code}")
        log_to_excel(wi_id, issue_key, "Transition", "Failed", f"HTTP {r.status_code}")


def download_images_to_ado_attachments(url, wi_id=None, issue_key=None):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    filename = query["fileName"][0] if "fileName" in query else os.path.basename(parsed.path)
    output_file = os.path.join(OUTPUT_DIR, filename)
    response = api_request("get", url, wi_id=wi_id, issue_key=issue_key,
                            step=f"Download Image ({filename})",
                            auth=HTTPBasicAuth("", ADO_PAT), stream=True)
    if response.status_code == 200:
        with open(output_file, "wb") as f:
            for chunk in response.iter_content(1024):
                f.write(chunk)
        return output_file
    return None


def jira_add_comment_for_link(issue_key: str, body: str, wi_id=None):
    url = f"{JIRA_URL}/rest/api/2/issue/{issue_key}/comment"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    response = api_request("post", url, wi_id=wi_id, issue_key=issue_key,
                           step="Add Comment (link)", headers=headers, auth=jira_auth(), json={"body": body})
    if response.status_code == 201:
        update_wi_row(wi_id, "Add Comment (link)", "Success", f"Comment: {body[:60]}...")
    else:
        update_wi_row(wi_id, "Add Comment (link)", "Failed",
                      f"HTTP {response.status_code}: {response.text[:80]}")


# ============================================================
# MENTION RESOLUTION — GUID MAP
# ============================================================

def _build_ado_guid_to_jira_map() -> Dict[str, str]:
    result: Dict[str, str] = {}
    guid_map_file = "ado_guid_map.csv"
    if os.path.exists(guid_map_file):
        try:
            import csv
            with open(guid_map_file, "r", encoding="utf-8-sig") as fh:
                first = fh.readline()
                delim = "\t" if "\t" in first else ","
                fh.seek(0)
                name_count = 0
                acct_count = 0
                for row_num, row in enumerate(csv.reader(fh, delimiter=delim), 1):
                    if not row or len(row) < 2:
                        continue
                    guid = row[0].strip().lower()
                    value = row[1].strip()
                    if row_num == 1 and not _ADO_GUID_RE.match(guid):
                        continue
                    if not guid or not value:
                        continue
                    if ":" in value:
                        result[guid] = value
                        acct_count += 1
                    else:
                        _ADO_IDENTITY_CACHE[guid] = value
                        name_count += 1
            parts = []
            if acct_count:
                parts.append(f"{acct_count} Jira account mappings")
            if name_count:
                parts.append(f"{name_count} display name mappings")
            if parts:
                print(f"✅ Loaded {' + '.join(parts)} from {guid_map_file}")
        except Exception as e:
            print(f"⚠️  Could not load {guid_map_file}: {e}")
    return result


_ADO_GUID_MAP: Dict[str, str] = {}
_ADO_GUID_MAP_LOADED = False


def _get_ado_guid_map() -> Dict[str, str]:
    global _ADO_GUID_MAP, _ADO_GUID_MAP_LOADED
    if not _ADO_GUID_MAP_LOADED:
        _ADO_GUID_MAP = _build_ado_guid_to_jira_map()
        _ADO_GUID_MAP_LOADED = True
    return _ADO_GUID_MAP


def _resolve_mention(href: str, data_vss_mention: str, display_name: str) -> str:
    guid_map = _get_ado_guid_map()
    if data_vss_mention:
        guids = _ADO_GUID_RE.findall(data_vss_mention)
        for g in guids:
            acct = guid_map.get(g.lower())
            if acct:
                return f"[~accountId:{acct}]"
    if href:
        if href.lower().startswith("mailto:"):
            email = href[7:].strip().lower()
            acct = USER_MAP.get(email)
            if acct:
                return f"[~accountId:{acct}]"
        else:
            guids = _ADO_GUID_RE.findall(href)
            for g in guids:
                acct = guid_map.get(g.lower())
                if acct:
                    return f"[~accountId:{acct}]"
    clean_name = display_name or ""
    clean_name = _ADO_GUID_RE.sub("", clean_name)
    clean_name = clean_name.lstrip("@<").rstrip(">").strip()
    if not clean_name:
        if href and href.lower().startswith("mailto:"):
            clean_name = href[7:].split("@")[0].strip()
        if not clean_name:
            clean_name = "Unknown"
    return f"@{clean_name}"


# ============================================================
# COMMENT PARSER — handles BOTH markdown and HTML format
# ============================================================

def _parse_comment_html(html_text: str) -> List[Dict]:
    if not html_text:
        return []
    html_text = html.unescape(html_text)
    html_text = re.sub(r"(?i)<br\s*/?>", "\n", html_text)
    soup = BeautifulSoup(html_text, "html.parser")
    parts: List[Dict] = []
    text_buf: List[str] = []

    def flush_text():
        combined = "".join(text_buf)
        combined = re.sub(r" {2,}", " ", combined)
        combined = re.sub(r"\n{3,}", "\n\n", combined)
        combined = combined.strip()
        if combined:
            parts.append({"kind": "text", "value": combined})
        text_buf.clear()

    def _is_mention_link(tag) -> bool:
        if tag.get("data-vss-mention"):
            return True
        href = (tag.get("href") or "").strip()
        if "/_apis/Identities/" in href:
            return True
        if "vssps.visualstudio.com" in href:
            return True
        label = tag.get_text(strip=True)
        if href.startswith("mailto:") and label.startswith("@"):
            return True
        return False

    def walk(node):
        if isinstance(node, NavigableString):
            txt = str(node)
            if txt:
                text_buf.append(txt)
            return
        if not isinstance(node, BeautifulSoup) and not hasattr(node, 'name'):
            return
        name = node.name.lower() if node.name else ""
        if name == "img":
            flush_text()
            src = (node.get("src") or "").strip()
            if src:
                if src.startswith("data:"):
                    try:
                        import base64, uuid
                        header, b64data = src.split(",", 1)
                        mime = header.split(":")[1].split(";")[0]
                        ext = mime.split("/")[1]
                        filename = f"inline_image_{uuid.uuid4().hex[:8]}.{ext}"
                        local_path = os.path.join(OUTPUT_DIR, filename)
                        with open(local_path, "wb") as f:
                            f.write(base64.b64decode(b64data))
                        parts.append({"kind": "image_local", "path": local_path, "filename": filename})
                    except Exception as e:
                        log(f"   ⚠️ Failed to decode base64 image: {e}")
                else:
                    parts.append({"kind": "image", "src": src})
            return
        if name == "a":
            href = (node.get("href") or "").strip()
            label = node.get_text(strip=True) or href
            data_vss = node.get("data-vss-mention", "")
            if _is_mention_link(node):
                text_buf.append(_resolve_mention(href, data_vss, label))
            else:
                if href:
                    text_buf.append(f"[{label}|{href}]")
                else:
                    text_buf.append(label)
            return
        if name == "br":
            text_buf.append("\n")
            return
        # ---- TABLE → render as Jira wiki markup ----
        if name == "table":
            flush_text()
            jira_table_lines = []
            for tr in node.find_all("tr"):
                cells = tr.find_all(["td", "th"])
                if not cells:
                    continue
                # Determine if any cell is a <th> or it's the first row → header row
                is_header = any(c.name == "th" for c in cells)
                row_parts = []
                for cell in cells:
                    cell_text = cell.get_text(separator=" ", strip=True).replace("|", "\\|")
                    # Bold the text if it's a th
                    if cell.name == "th" or (cell.find("strong") or cell.find("b")):
                        cell_text = f"*{cell_text}*" if cell_text else " "
                    if not cell_text:
                        cell_text = " "
                    row_parts.append(cell_text)
                if is_header:
                    jira_table_lines.append("||" + "||".join(row_parts) + "||")
                else:
                    jira_table_lines.append("|" + "|".join(row_parts) + "|")
            if jira_table_lines:
                parts.append({"kind": "text", "value": "\n".join(jira_table_lines)})
            return

        is_block = name in {"p", "div", "li", "ul", "ol",
                             "h1", "h2", "h3", "h4", "h5", "h6",
                             "blockquote"}
        if is_block:
            flush_text()
            for child in node.children if hasattr(node, 'children') else []:
                walk(child)
            flush_text()
            return
        for child in node.children if hasattr(node, 'children') else []:
            walk(child)


    for top in soup.contents:
        walk(top)
    flush_text()
    return parts


# ============================================================
# IMPROVED COMMENT HANDLING — format detection, image extraction,
# malformed link fixing, link deduplication
# ============================================================

def detect_comment_format(comment: Dict) -> tuple:
    """
    Detect comment format and return (format_type, raw_text, rendered_text).

    PRIORITY: HTML > Markdown > Plain text.
    Prefers HTML when raw_text OR rendered_text looks like HTML to avoid
    raw HTML tags being passed through the markdown pipeline as literal text.

    Key case: ADO sometimes stores raw HTML in the `text` field but sets
    `format` to "markdown" or "text". We detect this by checking if raw_text
    itself contains HTML block-level tags (div, img, br, a, etc.).
    """
    comment_format = comment.get("format", "html").lower()
    raw_text = comment.get("text", "")
    rendered_text = comment.get("renderedText", "")

    def _looks_like_html(text: str) -> bool:
        return bool(re.search(r'<[a-zA-Z][^>]*>', text or ""))

    def _looks_like_block_html(text: str) -> bool:
        """Stronger check — raw_text contains block-level HTML tags like <div>, <img>, <br>."""
        return bool(re.search(r'<(div|img|br|p|table|ul|ol|li|h[1-6]|a\s)[^>]*>', text or "", re.IGNORECASE))

    def _looks_like_markdown(text: str) -> bool:
        return bool(re.search(r'(!\[|!\(|\*\*|\*[^*]|_[^_])', text or ""))

    if comment_format == "html":
        return ("html", raw_text, rendered_text)

    # If rendered_text looks like HTML, always use HTML path —
    # prevents duplicate links from markdown parsing
    if _looks_like_html(rendered_text):
        return ("html", raw_text, rendered_text)

    # KEY FIX: If raw_text itself is raw HTML (e.g. ADO stores <div>...<img>...<a>
    # in the text field but marks format as "markdown" or "text"), route to HTML parser.
    # Without this, the markdown pipeline passes the raw HTML through as literal text.
    if _looks_like_block_html(raw_text):
        return ("html", raw_text, raw_text)

    if comment_format == "markdown" and _looks_like_markdown(raw_text):
        return ("markdown", raw_text, rendered_text)

    if _looks_like_markdown(raw_text) and not _looks_like_html(raw_text):
        return ("markdown", raw_text, rendered_text)

    return ("plain", raw_text, rendered_text)


def _fix_ado_malformed_markdown_links(text: str) -> str:
    """
    Fix ADO's malformed markdown links.

    ADO produces several broken link patterns:

    1. Title-escaped:   [text](url &quot;url&quot;)  → [text](url)
    2. Angle+paren:     <[display_url>](real_url> "lower_url")
                        The display text starts with the URL and ends with >
                        The href has a trailing %3E (encoded >)
                        These appear THREE times for the same URL — collapse to one clean link.

    Example raw (after html.unescape):
        <[https://dev.azure.com/.../results>](https://dev.azure.com/.../results> "https://dev.azure.com/.../results%3e")
    Should become:
        [https://dev.azure.com/.../results](https://dev.azure.com/.../results)
    """
    import html as html_lib

    # Step 1: unescape HTML entities so we can work with real chars
    text = html_lib.unescape(text)

    # Step 2: collapse the ADO angle-bracket triple-link pattern.
    # Pattern: literal < then [display_ending_with_>](href_ending_with_> or %3E optional_title)
    # We want to emit a single clean [URL](URL).
    angle_triple = re.compile(
        r'<\[([^\]]+?)>?\]\([^\)]*?\)',
        re.DOTALL
    )

    def fix_angle_triple(m):
        # Extract the clean URL from the display text (strip trailing >)
        display = m.group(1).rstrip('>').strip()
        # Only treat as a URL link if it looks like a URL
        if display.startswith('http'):
            return f'[{display}]({display})'
        return m.group(0)  # leave unchanged if not a URL

    text = angle_triple.sub(fix_angle_triple, text)

    # Step 3: fix remaining title-escaped links: [text](url "title") or [text](url &quot;title&quot;)
    # After unescaping step 1, &quot; becomes " so both cases reduce to [text](url "title")
    title_pattern = re.compile(r'\[([^\]]+)\]\((\S+)\s+"[^"]*"\)')

    def fix_title_link(m):
        link_text = m.group(1)
        url = m.group(2).rstrip('>').strip()
        return f'[{link_text}]({url})'

    text = title_pattern.sub(fix_title_link, text)

    return text


def _deduplicate_links_in_parts(parts: List[Dict]) -> None:
    """
    Deduplicate Jira-style [text|url] links across text parts — modifies in-place.
    Once a URL has been seen, subsequent occurrences are removed.
    """
    seen_links: Dict[str, str] = {}

    for part in parts:
        if part["kind"] != "text":
            continue

        text = part["value"]
        link_pattern = r'\[([^\]]+)\|([^\]]+)\]'

        def replace_link(match):
            display = match.group(1)
            url = match.group(2)
            if url in seen_links:
                return ""
            seen_links[url] = display
            return match.group(0)

        deduplicated = re.sub(link_pattern, replace_link, text)
        deduplicated = re.sub(r' +', ' ', deduplicated)
        deduplicated = re.sub(r'\n\n+', '\n\n', deduplicated)
        part["value"] = deduplicated.strip()


def _parse_comment_markdown_improved(text: str, mention_map: Dict[str, str]) -> List[Dict]:
    """
    Parse markdown comment into parts, extracting inline images separately.
    Also fixes malformed ADO links and resolves @mentions.
    """
    if not text:
        return []

    parts: List[Dict] = []

    # Fix ADO's malformed link patterns; this also unescapes HTML entities internally
    text = _fix_ado_malformed_markdown_links(text)

    # Extract inline images: ![alt](url)
    image_pattern = r'!\[([^\]]*)\]\(([^)]+)\)'

    last_end = 0
    for match in re.finditer(image_pattern, text):
        text_before = text[last_end:match.start()]
        if text_before.strip():
            resolved = _resolve_markdown_mentions(text_before, mention_map)
            resolved = _convert_markdown_to_jira_wiki(resolved)
            if resolved.strip():
                parts.append({"kind": "text", "value": resolved.strip()})

        image_url = match.group(2).strip()
        if image_url:
            parts.append({"kind": "image", "src": image_url})

        last_end = match.end()

    # Remaining text after last image
    text_after = text[last_end:]
    if text_after.strip():
        resolved = _resolve_markdown_mentions(text_after, mention_map)
        resolved = _convert_markdown_to_jira_wiki(resolved)
        if resolved.strip():
            parts.append({"kind": "text", "value": resolved.strip()})

    # If no images found at all, return the whole thing as one text part
    if not parts:
        resolved_text = _resolve_markdown_mentions(text, mention_map)
        resolved_text = _convert_markdown_to_jira_wiki(resolved_text)
        if resolved_text.strip():
            return [{"kind": "text", "value": resolved_text.strip()}]

    _deduplicate_links_in_parts(parts)
    return parts


def build_comment_body_with_images(parts: List[Dict], image_url_map: Dict[str, str],
                                    meta_line: str, issue_key: str = None) -> str:
    """
    Assemble the final Jira comment body, interleaving text and uploaded images
    in the order they appeared in the original comment.
    """
    body_parts: List[str] = [meta_line]

    for p in parts:
        if p["kind"] == "text":
            txt = p["value"].strip()
            if txt:
                txt = re.sub(r'\n{3,}', '\n\n', txt)
                body_parts.append(txt)
        elif p["kind"] in ("image", "image_local"):
            key = p.get("src") or p.get("path")
            jira_url = image_url_map.get(key)
            if jira_url:
                body_parts.append(f"!{jira_url}!")
            else:
                body_parts.append(f"[Image failed to load]")

    return "\n\n".join(body_parts).strip()


def process_comment_and_post(issue_key: str, comment: Dict, wi_id=None, comment_index: int = 0,
                              author: str = "Unknown", created_str: str = ""):
    """
    Process and post an ADO comment to Jira.
    Handles HTML/markdown format detection, inline image download+upload,
    URL deduplication, and @mention resolution.
    """
    meta_line = f"*Originally commented by {author} on {created_str}*"

    comment_format, raw_text, rendered_text = detect_comment_format(comment)

    log(f"   💬 Comment[{comment_index}]: format={comment_format}, has_content={bool(raw_text or rendered_text)}")

    # Empty comment — post meta-line only
    if not raw_text or not raw_text.strip():
        if not rendered_text or not rendered_text.strip():
            _post_text_comment(issue_key, meta_line, wi_id=wi_id, comment_index=comment_index)
            update_wi_row(wi_id, f"Comment[{comment_index}]", "Success", "Meta-only (empty body)")
            return

    # Parse based on detected format
    if comment_format == "markdown":
        log(f"   🔍 Resolving mentions for comment {comment_index} (markdown)...")
        mention_map = _build_mention_map_from_comment(comment)
        parts = _parse_comment_markdown_improved(raw_text, mention_map)

    elif comment_format == "html":
        parts = _parse_comment_html(rendered_text or raw_text)

    else:  # plain text — run through markdown improved for mention resolution
        log(f"   🔍 Resolving mentions for comment {comment_index} (plain)...")
        mention_map = _build_mention_map_from_comment(comment)
        parts = _parse_comment_markdown_improved(raw_text, mention_map)

    if not parts:
        _post_text_comment(issue_key, meta_line, wi_id=wi_id, comment_index=comment_index)
        update_wi_row(wi_id, f"Comment[{comment_index}]", "Success", "Meta-only (no content)")
        return

    has_images = any(p["kind"] in ("image", "image_local") for p in parts)
    has_text = any(p["kind"] == "text" for p in parts)

    log(f"   📝 Comment[{comment_index}]: {len(parts)} parts | text={has_text} | images={sum(1 for p in parts if p['kind'] == 'image')}")

    # No images — post as plain text comment
    if not has_images:
        full_text = "\n\n".join(p["value"] for p in parts if p["kind"] == "text").strip()
        body = f"{meta_line}\n\n{full_text}" if full_text else meta_line
        _post_text_comment(issue_key, body, wi_id=wi_id, comment_index=comment_index)
        update_wi_row(wi_id, f"Comment[{comment_index}]", "Success",
                      f"Text-only ({len(body)} chars)")
        return

    # Has images — download from ADO and upload to Jira
    image_url_map: Dict[str, str] = {}
    img_upload_count = 0
    img_fail_count = 0

    for p in parts:
        if p["kind"] not in ("image", "image_local"):
            continue

        if p["kind"] == "image_local":
            src_key = p["path"]
            local_file = p["path"]
            filename = p["filename"]
        else:
            src_key = p["src"]
            if src_key in image_url_map:
                continue
            parsed_url = urlparse(src_key)
            query = parse_qs(parsed_url.query or "")
            filename = query.get("fileName", [f"image_{comment_index}.png"])[0]
            log(f"   📥 Downloading image: {filename}")
            local_file = download_images_to_ado_attachments(src_key)

        if src_key in image_url_map:
            continue

        if not local_file:
            img_fail_count += 1
            image_url_map[src_key] = None
            continue

        log(f"   📤 Uploading image to Jira: {filename}")
        upload_info = jira_upload_attachment(issue_key, local_file)

        if upload_info and upload_info.get("content"):
            image_url_map[src_key] = upload_info["content"]
            img_upload_count += 1
        elif upload_info and upload_info.get("id"):
            base = clean_base(JIRA_URL)
            image_url_map[src_key] = f"{base}/rest/api/2/attachment/content/{upload_info['id']}"
            img_upload_count += 1
        else:
            img_fail_count += 1
            image_url_map[src_key] = None

        try:
            if os.path.exists(local_file):
                os.remove(local_file)
        except Exception:
            pass

    # Build and post final comment body with images interleaved
    final_body = build_comment_body_with_images(parts, image_url_map, meta_line, issue_key)

    comment_url = f"{clean_base(JIRA_URL)}/rest/api/2/issue/{issue_key}/comment"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    r = api_request("post", comment_url, wi_id=wi_id, issue_key=issue_key,
                    step=f"Post Comment[{comment_index}]",
                    auth=jira_auth(), headers=headers, json={"body": final_body})

    if r.status_code in (200, 201):
        log(f"   ✅ Comment[{comment_index}] posted ({img_upload_count} images OK, {img_fail_count} failed)")
        update_wi_row(wi_id, f"Comment[{comment_index}]", "Success",
                      f"Text + {img_upload_count} images")
    else:
        log(f"   ❌ Comment[{comment_index}] failed: {r.status_code}")
        update_wi_row(wi_id, f"Comment[{comment_index}]", "Failed",
                      f"HTTP {r.status_code}")


def _post_text_comment(issue_key: str, body: str, wi_id=None, comment_index: int = 0):
    comment_url = f"{clean_base(JIRA_URL)}/rest/api/2/issue/{issue_key}/comment"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    r = api_request("post", comment_url, wi_id=wi_id, issue_key=issue_key,
                    step=f"Post Comment[{comment_index}]",
                    auth=jira_auth(), headers=headers, json={"body": body})
    if r.status_code not in (200, 201):
        log(f"   ❌ Comment[{comment_index}] post failed: {r.status_code} {r.text[:200]}")
        update_wi_row(wi_id, f"Comment[{comment_index}]", "Failed",
                      f"HTTP {r.status_code}: {r.text[:80]}")


def ado_api_to_ui_link(api_url):
    match = re.search(r'/workItems/(\d+)', api_url)
    if not match:
        return api_url
    workitem_id = match.group(1)
    return re.sub(r'_apis/wit/workItems/\d+', f'_workitems/edit/{workitem_id}', api_url)


def extract_wid(url):
    match = re.search(r'/workItems/(\d+)', url)
    return match.group(1) if match else None


def fetch_ado_workitem_title(wid):
    url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/workitems/{wid}?api-version=7.1"
    r = api_request("get", url, step=f"Fetch ADO Title ({wid})", auth=ado_auth())
    r.raise_for_status()
    data = r.json()
    return data["fields"].get("System.Title", "ADO Work Item"), data["fields"].get("System.WorkItemType", "")


def create_links_from_ado(wi, issue_key, wi_id=None):
    relations = wi.get("relations", [])
    if not relations:
        log_to_excel(wi_id, issue_key, "Create Links", "Skipped", "No relations in ADO work item")
        return
    base = clean_base(JIRA_URL)
    link_success = 0
    link_fail = 0
    for rel in relations:
        try:
            url = rel.get("url")
            rel_type = rel.get("attributes", {}).get("name", "Related")
            if not url or url.startswith("vstfs:///"):
                continue
            if "_apis/wit/workItems" not in url:
                continue
            wid_linked = extract_wid(url)
            if not wid_linked:
                continue
            title, _ = fetch_ado_workitem_title(wid_linked)
            ado_ui_url = ado_api_to_ui_link(url)
            payload = {"object": {"url": ado_ui_url, "title": f"[{rel_type}] {wid_linked} | {title}"}}
            link_url = f"{base}/rest/api/3/issue/{issue_key}/remotelink"
            r = api_request("post", link_url, wi_id=wi_id, issue_key=issue_key,
                            step=f"Create Remote Link ({rel_type})",
                            json=payload, auth=jira_auth(), headers={"Content-Type": "application/json"})
            if r.status_code in (200, 201):
                link_success += 1
                log_to_excel(wi_id, issue_key, "Create Link", "Success", f"[{rel_type}] ADO {wid_linked} linked")
            else:
                link_fail += 1
                log_to_excel(wi_id, issue_key, "Create Link", "Failed",
                             f"HTTP {r.status_code} for ADO {wid_linked}")
        except Exception as e:
            log_to_excel(wi_id, issue_key, "Create Link", "Error", str(e)[:100])
            link_fail += 1
    log_to_excel(wi_id, issue_key, "Create Links Summary", "Complete",
                 f"{link_success} succeeded, {link_fail} failed")


# ============================================================
# EXCEL TRACKING - IMPROVED
# ============================================================

wi_rows: Dict[str, Dict] = {}
system_log: List[Dict] = []
_LEAD_COLS = ["ADO_WorkItemID", "Jira_IssueKey", "Overall_Status"]


def _ensure_row(wi_id) -> str:
    key = str(wi_id) if wi_id is not None else "__system__"
    if key not in wi_rows:
        wi_rows[key] = {c: "" for c in _LEAD_COLS}
        wi_rows[key]["ADO_WorkItemID"] = wi_id or ""
    return key


def update_wi_row(wi_id, field: str, status: str, value: str = ""):
    """Log field status and message"""
    key = _ensure_row(wi_id)
    safe_field = field.replace(" ", "_").replace("[", "").replace("]", "")
    wi_rows[key][f"{safe_field}_Status"] = status
    if value:
        wi_rows[key][f"{safe_field}_Message"] = str(value)[:300]
    print(f"  [{wi_id or 'SYS'}] {field} → {status} | {value}")


def set_wi_key(wi_id, issue_key: str):
    key = _ensure_row(wi_id)
    wi_rows[key]["Jira_IssueKey"] = issue_key


def set_wi_overall(wi_id, status: str, notes: str = ""):
    key = _ensure_row(wi_id)
    wi_rows[key]["Overall_Status"] = status


def log_system(event: str, status: str, message: str = ""):
    system_log.append({
        "Timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Event": event, "Status": status, "Message": message
    })
    print(f"[SYSTEM] {event} → {status} | {message}")


def log_to_excel(wi_id, issue_key, step, status, message):
    if wi_id is None:
        log_system(step, status, message)
        return
    if issue_key:
        set_wi_key(wi_id, issue_key)
    update_wi_row(wi_id, step, status, message)


def migrate_all():
    ensure_dir(ATTACH_DIR)

    if os.path.exists(MAPPING_FILE):
        with open(MAPPING_FILE, "r") as f:
            mapping = json.load(f)
    else:
        mapping = {}

    wiql = (
        "SELECT [System.Id] FROM WorkItems WHERE [System.CreatedDate] >= '2026-02-21' "
        "AND [System.CreatedDate] <= '2026-02-28' AND [System.WorkItemType] = 'Defect'"
    )
    ids = ado_wiql_all_ids(wiql)
    if not ids:
        log("No work items found.")
        return

    log(f"📌 Found {len(ids)} work items.")

    SPECIFIC_ID = ["685285"]

    if SPECIFIC_ID:
        ids = SPECIFIC_ID
        log(f"🎯 Running migration for specific work items: {SPECIFIC_ID}")
    else:
        START_INDEX = 0
        MAX_TO_PROCESS = 1000
        ids = ids[START_INDEX:START_INDEX + MAX_TO_PROCESS]

    for batch in chunked(ids, WIQL_PAGE_SIZE):
        time.sleep(SLEEP_BETWEEN_CALLS)
        workitems = ado_get_workitems_by_ids(batch)
        workitems.sort(key=lambda w: w.get("id", 0))

        for wi in workitems:
            wi_id = int(wi.get("id"))
            wi_id_str = str(wi_id)
            log(f"--- ADO #{wi_id_str} ---")

            if wi_id_str in mapping:
                log_to_excel(wi_id, mapping[wi_id_str], "Migration", "Skipped", "Already migrated")
                continue

            # 1) Create Jira issue
            try:
                fields = build_jira_fields_from_ado(wi)
                issue_key = jira_create_issue(fields, wi_id=wi_id)
                if not issue_key:
                    continue
            except Exception as e:
                log_to_excel(wi_id, None, "Create Issue", "Error", str(e)[:100])
                continue

            # 2) Create remote links
            try:
                create_links_from_ado(wi, issue_key, wi_id=wi_id)
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Create Links", "Error", str(e)[:100])

            # 3) ReproSteps
            repro_steps_html = wi.get("fields", {}).get("Microsoft.VSTS.TCM.ReproSteps", "")
            repro_steps_html = fix_relative_urls_in_repro_steps(repro_steps_html)
            if repro_steps_html:
                try:
                    attachment_map = download_and_upload_reprosteps_images(
                        issue_key, repro_steps_html, wi_id=wi_id)
                    if attachment_map:
                        time.sleep(2)
                    verified_map = {}
                    for src, att_id in attachment_map.items():
                        base = clean_base(JIRA_URL)
                        verify_url = f"{base}/rest/api/3/attachment/{att_id}"
                        verify_response = api_request("get", verify_url, wi_id=wi_id, issue_key=issue_key,
                                                       step=f"Verify Attachment {att_id}", auth=jira_auth())
                        if verify_response.status_code == 200:
                            verified_map[src] = att_id
                    jira_repro_adf = convert_ado_reprosteps_to_jira_adf(repro_steps_html, verified_map, issue_key)
                    if jira_repro_adf.get("content"):
                        base = clean_base(JIRA_URL)
                        url = f"{base}/rest/api/3/issue/{issue_key}"
                        r = api_request("put", url, wi_id=wi_id, issue_key=issue_key,
                                        step="Update ReproSteps", auth=jira_auth(),
                                        headers={"Content-Type": "application/json"},
                                        json={"fields": {"customfield_12494": jira_repro_adf}})
                        if r.status_code in (200, 204):
                            log(f"   ✅ Updated ReproSteps for {issue_key}")
                            log_to_excel(wi_id, issue_key, "Update ReproSteps", "Success", "ReproSteps updated")
                        else:
                            log_to_excel(wi_id, issue_key, "Update ReproSteps", "Failed", f"HTTP {r.status_code}")
                except Exception as e:
                    log_to_excel(wi_id, issue_key, "Update ReproSteps", "Error", str(e)[:100])
            else:
                log_to_excel(wi_id, issue_key, "Update ReproSteps", "Skipped", "No ReproSteps found")

            # # 4) Steps field
            # try:
            #     url = f"{JIRA_URL}rest/api/3/issue/{issue_key}"
            #     headers = {"Content-Type": "application/json"}
            #     if steps_payload and steps_payload.strip() != " ":
            #         r = api_request("put", url, wi_id=wi_id, issue_key=issue_key,
            #                         step="Update Steps", auth=jira_auth(), headers=headers, data=steps_payload)
            #         if r.status_code in (200, 204):
            #             log_to_excel(wi_id, issue_key, "Update Steps", "Success", "Steps updated")
            #         else:
            #             log_to_excel(wi_id, issue_key, "Update Steps", "Failed", f"HTTP {r.status_code}")
            #     else:
            #         log_to_excel(wi_id, issue_key, "Update Steps", "Skipped", "No steps data")
            # except Exception as e:
            #     log_to_excel(wi_id, issue_key, "Update Steps", "Error", str(e)[:100])

            # 5) Description — NOW USES improved_process_description_to_adf FOR TABLE SUPPORT
            try:
                raw_desc = wi.get("fields", {}).get("System.Description", "")
                if raw_desc:
                    desc_adf = improved_process_description_to_adf(issue_key, raw_desc, wi_id=wi_id)
                    base = clean_base(JIRA_URL)
                    url = f"{base}/rest/api/3/issue/{issue_key}"
                    r = api_request("put", url, wi_id=wi_id, issue_key=issue_key,
                                    step="Update Description", auth=jira_auth(),
                                    headers={"Content-Type": "application/json"},
                                    json={"fields": {"description": desc_adf}})
                    if r.status_code in (200, 204):
                        log_to_excel(wi_id, issue_key, "Update Description", "Success", "Description updated")
                    else:
                        log_to_excel(wi_id, issue_key, "Update Description", "Failed", f"HTTP {r.status_code}")
                else:
                    log_to_excel(wi_id, issue_key, "Update Description", "Skipped", "No description")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Update Description", "Error", str(e)[:100])

            # Save mapping
            mapping[wi_id_str] = issue_key
            with open(MAPPING_FILE, "w") as f:
                json.dump(mapping, f, indent=2)

            # 5b) Proposed Fix — needs issue_key for image upload
            try:
                proposed_fix_html = wi.get("fields", {}).get("Microsoft.VSTS.CMMI.ProposedFix", "")
                if proposed_fix_html:
                    proposed_fix_adf = improved_process_description_to_adf(
                        issue_key, proposed_fix_html, wi_id=wi_id)
                    base = clean_base(JIRA_URL)
                    url = f"{base}/rest/api/3/issue/{issue_key}"
                    r = api_request("put", url, wi_id=wi_id, issue_key=issue_key,
                                    step="Update Proposed Fix", auth=jira_auth(),
                                    headers={"Content-Type": "application/json"},
                                    json={"fields": {"customfield_12787": proposed_fix_adf}})
                    if r.status_code in (200, 204):
                        log_to_excel(wi_id, issue_key, "Update Proposed Fix", "Success", "Proposed Fix updated")
                    else:
                        log_to_excel(wi_id, issue_key, "Update Proposed Fix", "Failed", f"HTTP {r.status_code}")
                else:
                    log_to_excel(wi_id, issue_key, "Update Proposed Fix", "Skipped", "No Proposed Fix")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Update Proposed Fix", "Error", str(e)[:100])

            # 5c) QA Comment
            try:
                qa_comment_html = wi.get("fields", {}).get("Custom.QAComment", "")
                if qa_comment_html:
                    qa_comment_adf = improved_process_description_to_adf(
                        issue_key, qa_comment_html, wi_id=wi_id)
                    base = clean_base(JIRA_URL)
                    url = f"{base}/rest/api/3/issue/{issue_key}"
                    r = api_request("put", url, wi_id=wi_id, issue_key=issue_key,
                                    step="Update QAComment", auth=jira_auth(),
                                    headers={"Content-Type": "application/json"},
                                    json={"fields": {"customfield_12868": qa_comment_adf}})
                    if r.status_code in (200, 204):
                        log_to_excel(wi_id, issue_key, "Update QAComment", "Success", "QA Comment updated")
                    else:
                        log_to_excel(wi_id, issue_key, "Update QAComment", "Failed", f"HTTP {r.status_code}")
                else:
                    log_to_excel(wi_id, issue_key, "Update QAComment", "Skipped", "No QA Comment")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Update QAComment", "Error", str(e)[:100])

            # 5d) CTMS Comment
            try:
                ctms_comment_html = wi.get("fields", {}).get("Custom.CTMSComment", "")
                if ctms_comment_html:
                    ctms_comment_adf = improved_process_description_to_adf(
                        issue_key, ctms_comment_html, wi_id=wi_id)
                    base = clean_base(JIRA_URL)
                    url = f"{base}/rest/api/3/issue/{issue_key}"
                    r = api_request("put", url, wi_id=wi_id, issue_key=issue_key,
                                    step="Update CTMSComment", auth=jira_auth(),
                                    headers={"Content-Type": "application/json"},
                                    json={"fields": {"customfield_12869": ctms_comment_adf}})
                    if r.status_code in (200, 204):
                        log_to_excel(wi_id, issue_key, "Update CTMSComment", "Success", "CTMS Comment updated")
                    else:
                        log_to_excel(wi_id, issue_key, "Update CTMSComment", "Failed", f"HTTP {r.status_code}")
                else:
                    log_to_excel(wi_id, issue_key, "Update CTMSComment", "Skipped", "No CTMS Comment")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Update CTMSComment", "Error", str(e)[:100])

            # 5e) Trend Notes Comment
            try:
                trend_notes_html = wi.get("fields", {}).get("Custom.TrendNotesComment", "")
                if trend_notes_html:
                    trend_notes_adf = improved_process_description_to_adf(
                        issue_key, trend_notes_html, wi_id=wi_id)
                    base = clean_base(JIRA_URL)
                    url = f"{base}/rest/api/3/issue/{issue_key}"
                    r = api_request("put", url, wi_id=wi_id, issue_key=issue_key,
                                    step="Update TrendNotesComment", auth=jira_auth(),
                                    headers={"Content-Type": "application/json"},
                                    json={"fields": {"customfield_12870": trend_notes_adf}})
                    if r.status_code in (200, 204):
                        log_to_excel(wi_id, issue_key, "Update TrendNotesComment", "Success", "Trend Notes Comment updated")
                    else:
                        log_to_excel(wi_id, issue_key, "Update TrendNotesComment", "Failed", f"HTTP {r.status_code}")
                else:
                    log_to_excel(wi_id, issue_key, "Update TrendNotesComment", "Skipped", "No Trend Notes Comment")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Update TrendNotesComment", "Error", str(e)[:100])

            # 5f) Corrective Action Plan
            try:
                corrective_action_html = wi.get("fields", {}).get("Microsoft.VSTS.CMMI.CorrectiveActionPlan", "")
                if corrective_action_html:
                    corrective_action_adf = improved_process_description_to_adf(
                        issue_key, corrective_action_html, wi_id=wi_id)
                    base = clean_base(JIRA_URL)
                    url = f"{base}/rest/api/3/issue/{issue_key}"
                    r = api_request("put", url, wi_id=wi_id, issue_key=issue_key,
                                    step="Update CorrectiveActionPlan", auth=jira_auth(),
                                    headers={"Content-Type": "application/json"},
                                    json={"fields": {"customfield_11757": corrective_action_adf}})
                    if r.status_code in (200, 204):
                        log_to_excel(wi_id, issue_key, "Update CorrectiveActionPlan", "Success", "Corrective Action Plan updated")
                    else:
                        log_to_excel(wi_id, issue_key, "Update CorrectiveActionPlan", "Failed", f"HTTP {r.status_code}")
                else:
                    log_to_excel(wi_id, issue_key, "Update CorrectiveActionPlan", "Skipped", "No Corrective Action Plan")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Update CorrectiveActionPlan", "Error", str(e)[:100])

            # 6) Transition
            try:
                ado_state = wi.get("fields", {}).get("System.State", "New")
                jira_transition_issue(issue_key, ado_state, wi_id=wi_id)
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Transition", "Error", str(e)[:100])

            # 7) Attachments
            try:
                relations = wi.get("relations", [])
                attachments_to_upload = [
                    (rel.get("url"), rel.get("attributes", {}).get("name", "attachment"))
                    for rel in relations
                    if rel.get("rel") == "AttachedFile" and rel.get("url")
                ]
                if attachments_to_upload:
                    for att_url, att_filename in attachments_to_upload:
                        local_path = ado_download_attachment(att_url, att_filename, wi_id=wi_id, issue_key=issue_key)
                        if local_path and os.path.exists(local_path):
                            jira_upload_attachment(issue_key, local_path, wi_id=wi_id)
                            try:
                                os.remove(local_path)
                            except Exception:
                                pass
                    log_to_excel(wi_id, issue_key, "Attachments", "Success", f"Uploaded {len(attachments_to_upload)} files")
                else:
                    log_to_excel(wi_id, issue_key, "Attachments", "Skipped", "No attachments")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Attachments", "Error", str(e)[:100])

            # 8) Comments
            try:
                comments = ado_get_comments(wi_id)
                if comments:
                    update_wi_row(wi_id, "Comments_Total", "Info", str(len(comments)))
                    ok_count = 0
                    fail_count = 0
                    for idx, c in enumerate(reversed(comments)):
                        author = (c.get("createdBy") or {}).get("displayName", "Unknown")
                        created_date = c.get("createdDate", "")
                        try:
                            dt = datetime.strptime(created_date, "%Y-%m-%dT%H:%M:%S.%fZ")
                            created_str = dt.strftime("%d %b %Y %H:%M")
                        except Exception:
                            created_str = created_date
                        log(f"   💬 Processing comment {idx + 1}/{len(comments)} by {author} on {created_str}")
                        try:
                            process_comment_and_post(
                                issue_key, c,
                                wi_id=wi_id, comment_index=idx + 1,
                                author=author, created_str=created_str
                            )
                            ok_count += 1
                        except Exception as e:
                            log(f"   ❌ Comment {idx + 1} failed: {e}")
                            update_wi_row(wi_id, f"Comment[{idx + 1}]", "Error", str(e)[:100])
                            fail_count += 1
                    update_wi_row(wi_id, "Comments_Summary", "Complete",
                                  f"{ok_count} OK, {fail_count} failed of {len(comments)}")
                else:
                    update_wi_row(wi_id, "Comments_Total", "Skipped", "No comments in ADO")
            except Exception as e:
                update_wi_row(wi_id, "Comments", "Error", str(e)[:100])

            set_wi_overall(wi_id, "Complete")
            log(f"✅ Work item ADO #{wi_id_str} → {issue_key} migration complete")

    log("🎉 Migration completed.")
    log_system("Migration Complete", "Success", "All work items processed")

    # Cleanup
    try:
        for file in os.listdir("ado_attachments"):
            try:
                os.remove(os.path.join("ado_attachments", file))
            except Exception:
                pass
    except Exception as e:
        log_system("Cleanup", "Error", str(e)[:100])

    # Save Excel
    try:
        if wi_rows:
            all_cols: List[str] = list(_LEAD_COLS)
            for row in wi_rows.values():
                for col in row:
                    if col not in all_cols:
                        all_cols.append(col)
            rows_data = []
            for row in wi_rows.values():
                if row.get("ADO_WorkItemID") in (None, "", "__system__"):
                    continue
                rows_data.append({col: row.get(col, "") for col in all_cols})
            df_main = pd.DataFrame(rows_data, columns=all_cols)
            df_sys = pd.DataFrame(system_log) if system_log else pd.DataFrame(
                columns=["Timestamp", "Event", "Status", "Message"])
            with pd.ExcelWriter("migration_log.xlsx", engine="openpyxl") as writer:
                df_main.to_excel(writer, sheet_name="WorkItems", index=False)
                df_sys.to_excel(writer, sheet_name="SystemLog", index=False)
                ws = writer.sheets["WorkItems"]
                for col_cells in ws.columns:
                    max_len = max((len(str(c.value or "")) for c in col_cells), default=10)
                    ws.column_dimensions[col_cells[0].column_letter].width = min(max_len + 4, 60)
            print(f"✅ Migration log saved: migration_log.xlsx")
        else:
            print("⚠️ No work item rows to save.")
    except Exception as e:
        print(f"❌ Failed to save migration_log.xlsx: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    migrate_all()