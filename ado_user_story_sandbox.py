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

# CODE 1 DIFFERENCE — "User Story" maps to "User Story" in Code 1.
# In this file (Code 2) it maps to "Story" because the target Jira project
# uses "Story" as the issue type name rather than "User Story".
WORKITEM_TYPE_MAP = {
    "Bug": "Bug",
    "Defect": "Defect",
    "Epic": "Epic",
    "Feature": "Feature",
    "Hotfix": "Hotfix",
    "Issue": "Issue",
    "Joes Test": "Joes Test",
    "Portfolio Epic": "Portfolio Epic",
    "Post Lockdown": "Post Lockdown",
    "Request": "Request",
    "RIDA (disabled)": "RIDA (disabled)",
    "Risk (disabled)": "Risk (disabled)",
    "Task": "Task",
    "Test Case": "Epic",
    "Test Plan": "Test Plan",
    "Test Suite": "Test Suite",
    "User Story": "Story"
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

# CODE 1 DIFFERENCE — Code 1's STATE_MAP has additional/different entries:
#   "Under Investigation" -> "In Refinement"   (present in Code 1, absent here)
#   "Waiting for customer" -> "Waiting for customer"  (present in Code 1, absent here)
#   "In Refinement" -> "In Refinement"  (Code 1) vs "REFINEMENT" (this file)
#   "Test Complete" -> "Ready to Release" (Code 1) vs "Ready for Release" (this file)
# Code 2 has entries not in Code 1:
#   "Blocked" -> "Hold"
# These differences reflect the different Jira workflow configurations between
# the Bug project (Code 1) and the User Story project (Code 2).
STATE_MAP = {
    "New": "New",
    "In Refinement": "REFINEMENT",
    "Ready": "Ready",
    "Blocked": "Hold",
    "In Development": "In Progress",
    "Development Complete": "Review",
    "In Test": "Testing",
    "Test Complete": "Ready for Release",
    "Closed": "Done",
    "Removed": "Cancelled"
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


# CODE 1 DIFFERENCE — Code 1's _resolve_markdown_mentions adds a pre-processing step
# at the very top of the function before any mention substitution:
#
#   import html as html_lib
#   text = html_lib.unescape(text)
#
# This ensures that HTML entities (e.g. &amp;, &quot;, emoji encoded as &#x1F600;) in
# the raw markdown text are decoded to their real characters BEFORE @<GUID> patterns
# are resolved. Without this, if the text arrived from ADO with encoded entities, the
# final comment body can contain raw entity strings instead of readable characters.
# Code 2 omits this unescape step, so entities are left as-is in the output.
def _resolve_markdown_mentions(text: str, mention_map: Dict[str, str]) -> str:
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


# CODE 1 DIFFERENCE — Code 1 has a heavily expanded _convert_markdown_to_jira_wiki
# implementation. The version here (Code 2) only handles bold and italic.
# Code 1's version adds the following capabilities that are missing here:
#
#   1. _BOLD_START / _BOLD_END sentinel constants to avoid bold/italic regex collision.
#   2. _inline_md_to_jira(text) helper that handles per-line inline conversions:
#        - Inline code:       `code`            → {{code}}
#        - Bold+italic:       ***text***        → *_text_*
#        - Bold (sentinels):  **text**          → *text*  (via sentinels, safe from italic step)
#        - Italic:            *text*            → _text_  (single * only, after bold extracted)
#        - Markdown links:    [text](url)       → [text|url]  (skips image links starting with !)
#        - Angle-bracket URLs: <https://...>   → [https://...]
#   3. Full block-level parsing by splitting on '\n' and iterating lines:
#        - ATX headings:      ### Heading       → h3. Heading  (strips trailing # too)
#        - GFM pipe tables:   | col | col |     → || col || col ||  (header row gets ||...||,
#                             |-----|-----|        data rows get |...|, separator rows are skipped,
#                                                  <br> tags inside cells are stripped)
#        - Unordered lists:   * item / - item   → * item  (depth controlled by leading spaces ÷ 2)
#        - Ordered lists:     1. item           → # item  (depth controlled by leading spaces ÷ 2)
#        - Regular lines:     pass through _inline_md_to_jira for inline conversion
#
# Code 2's version is two simple regex substitutions (bold and italic only) with no
# heading, table, list, inline-code, or link support. This means markdown-formatted
# comments from User Story work items in Code 2 lose all structure except bold/italic.
def _convert_markdown_to_jira_wiki(text: str) -> str:
    text = re.sub(r'\*\*(.+?)\*\*', r'*\1*', text)
    text = re.sub(r'(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)', r'_\1_', text)
    return text


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
# TABLE CONVERSION FUNCTIONS
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


# CODE 1 DIFFERENCE — Code 1 defines a fix_relative_urls_in_repro_steps() function
# that is NOT present in this file (Code 2). Code 1 calls it in migrate_all() on the
# raw ReproSteps HTML immediately before processing, like so:
#
#   repro_steps_html = fix_relative_urls_in_repro_steps(repro_steps_html)
#
# The function uses a regex to find relative URLs of the form /HESource/... in src=""
# and href="" attributes, and rewrites them to absolute Azure DevOps URLs:
#
#   def fix_relative_urls_in_repro_steps(repro_html: str) -> str:
#       pattern = r'((?:src|href)=")(/HESource/[^"]*)'
#       def replace_url(match):
#           return match.group(1) + "https://dev.azure.com" + match.group(2)
#       return re.sub(pattern, replace_url, repro_html)
#
# This matters for Bug work items where ADO stores embedded images with relative paths.
# Code 2 skips this step because User Story work items do not use those relative URLs.


def download_and_upload_reprosteps_images(issue_key: str, repro_html: str, wi_id=None) -> Dict[str, str]:
    attachment_map = {}
    if not repro_html:
        return attachment_map
    soup = BeautifulSoup(repro_html, "html.parser")
    for img in soup.find_all("img"):
        src = img.get("src")
        if src and ATTACH_URL_SUBSTR in src and src not in attachment_map:
            filename = parse_qs(urlparse(src).query or "").get("fileName", ["attachment.png"])[0]
            local_file = ado_download_attachment(src, filename, wi_id=wi_id, issue_key=issue_key)
            if not local_file:
                continue
            upload_info = jira_upload_attachment(issue_key, local_file, wi_id=wi_id)
            if upload_info and upload_info.get("id"):
                attachment_map[src] = upload_info["id"]
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
    # CODE 1 DIFFERENCE — Code 1 enables the steps_formatter block (not commented out).
    # It reads Microsoft.VSTS.TCM.Steps (the structured XML test steps field) and calls
    # steps_formatter() to convert it into a Jira ADF table stored in customfield_10632.
    # This is relevant for Bug/Test Case work items which carry test steps.
    # Code 2 comments this out because User Story work items do not have test steps.
    # steps = f.get("Microsoft.VSTS.TCM.Steps", " ")
    # if steps:
    #     try:
    #         steps_payload = steps_formatter(steps)
    #         log_to_excel(wi_id, None, "Steps Parsing", "Success", "Parsed test steps")
    #     except Exception as e:
    #         log_to_excel(wi_id, None, "Steps Parsing", "Failed", str(e)[:100])

    summary = f.get("System.Title", "No Title")
    raw_desc = f.get("System.Description", "")
    ado_type = f.get("System.WorkItemType", "Story")
    jira_issuetype = WORKITEM_TYPE_MAP.get(ado_type, "Story")
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

    # CODE 1 DIFFERENCE — Code 1 does NOT map Microsoft.VSTS.Common.Priority using PRIORITY_MAP.
    # Instead, Code 1 maps priority exclusively from Custom.BugPriority using BUG_PRIORITY_MAP
    # (P1→Blocker, P2→High, P3→Low, P4→Trivial). This is because Bug work items carry a custom
    # BugPriority field (P1–P4) while User Story work items use the standard integer Priority field.
    # Code 2 reads Microsoft.VSTS.Common.Priority (integer 1–4) and maps via PRIORITY_MAP.
    # Priority
    ado_priority_val = f.get("Microsoft.VSTS.Common.Priority")
    try:
        ado_priority_int = int(ado_priority_val) if ado_priority_val is not None else None
    except Exception:
        ado_priority_int = None

    jira_priority_name = PRIORITY_MAP.get(ado_priority_int or -1)

    if jira_priority_name:
        try:
            fields["priority"] = {"name": jira_priority_name}
            log_to_excel(wi_id, None, "Priority", "Success", f"ADO: {ado_priority_int} → Jira: {jira_priority_name}")
        except Exception as e:
            log_to_excel(wi_id, None, "Priority", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Priority", "Skipped", "No priority mapping")

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

    # Priority Rank
    priority_rank = f.get("Custom.PriorityRank")
    if priority_rank is not None:
        try:
            fields["customfield_11700"] = float(priority_rank)
            log_to_excel(wi_id, None, "Priority Rank", "Success", f"Value: {priority_rank}")
        except ValueError as e:
            log_to_excel(wi_id, None, "Priority Rank", "Failed", str(e)[:100])

    # Publish Date
    # CODE 1 DIFFERENCE — Code 1 does NOT map PublishDate (customfield_12173).
    # This is a User Story-specific scheduling field not present on Bug work items.
    publish_date_val = f.get("Custom.PublishDate")
    if publish_date_val:
        try:
            publish_date = convert_ado_datetime(publish_date_val)
            if publish_date:
                fields["customfield_12173"] = publish_date
                log_to_excel(wi_id, None, "Publish Date", "Success", publish_date_val[:10])
        except Exception as e:
            log_to_excel(wi_id, None, "Publish Date", "Failed", str(e)[:100])

    # Earliest Effective Date
    # CODE 1 DIFFERENCE — Code 1 does NOT map EarliestEffectiveDate (customfield_12560).
    # This is a User Story-specific regulatory/scheduling field absent from Bug work items.
    earliest_effective_date_val = f.get("Custom.EarliestEffectiveDate")
    if earliest_effective_date_val:
        try:
            earliest_effective_date = convert_ado_datetime(earliest_effective_date_val)
            if earliest_effective_date:
                fields["customfield_12560"] = earliest_effective_date
                log_to_excel(wi_id, None, "Earliest Effective Date", "Success", earliest_effective_date_val[:10])
        except Exception as e:
            log_to_excel(wi_id, None, "Earliest Effective Date", "Failed", str(e)[:100])

    # Sample Claims Status
    # CODE 1 DIFFERENCE — Code 1 does NOT map SampleClaimsStatus (customfield_12561).
    # This is a User Story-specific field not present on Bug work items.
    sample_claims_status = f.get("Custom.SampleClaimsStatus")
    if sample_claims_status:
        fields["customfield_12561"] = {"value": sample_claims_status}
        log_to_excel(wi_id, None, "Sample Claims Status", "Success", sample_claims_status)

    # MMS Status
    # CODE 1 DIFFERENCE — Code 1 does NOT map MMSStatus (customfield_12562).
    # This is a User Story-specific field not present on Bug work items.
    mms_status = f.get("Custom.MMSStatus")
    if mms_status:
        fields["customfield_12562"] = {"value": mms_status}
        log_to_excel(wi_id, None, "MMS Status", "Success", mms_status)

    # Release Notes Status
    release_notes_status = f.get("Custom.ReleaseNotesStatus")
    if release_notes_status:
        fields["customfield_11701"] = {"value": release_notes_status}
        log_to_excel(wi_id, None, "Release Notes Status", "Success", release_notes_status)

    # Stock Updates
    # CODE 1 DIFFERENCE — Code 1 does NOT map StockUpdates (customfield_12563).
    # This is a User Story-specific multi-select field not present on Bug work items.
    stock_updates = f.get("Custom.StockUpdates")
    if stock_updates:
        if ";" in stock_updates:
            options = [opt.strip() for opt in stock_updates.split(";")]
        else:
            options = [stock_updates.strip()]
        fields["customfield_12563"] = [{"value": opt} for opt in options]

    # Retire Release
    # CODE 1 DIFFERENCE — Code 1 does NOT map RetireRelease (customfield_12596).
    # This is a User Story-specific lifecycle field not present on Bug work items.
    retire_release = f.get("Custom.RetireRelease")
    if retire_release:
        fields["customfield_12596"] = {"value": retire_release}
        log_to_excel(wi_id, None, "Retire Release", "Success", retire_release)

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

    # Customer Name
    customer_name = f.get("Custom.CustomerName")
    if customer_name:
        parts = [c.strip() for c in customer_name.split(";") if c.strip()]
        fields["customfield_12350"] = [{"value": p} for p in parts]
        log_to_excel(wi_id, None, "Customer Name", "Success", f"Found {len(parts)} customers")

    # Medicaid State
    # CODE 1 DIFFERENCE — Code 1 does NOT map MedicaidState (customfield_12598).
    # This is a User Story-specific multi-select field not present on Bug work items.
    medicaid_state = f.get("Custom.MedicaidState")
    if medicaid_state:
        parts = [s.strip().strip('"') for s in medicaid_state.split(";") if s.strip()]
        fields["customfield_12598"] = [{"value": p} for p in parts]
        log_to_excel(wi_id, None, "Medicaid State", "Success", f"Found {len(parts)} states")

    # Provider Type
    provider_type = f.get("Custom.ProviderType")
    if provider_type:
        parts = [p.strip() for p in provider_type.split(";") if p.strip()]
        fields["customfield_12383"] = [{"value": p} for p in parts]
        log_to_excel(wi_id, None, "Provider Type", "Success", f"Found {len(parts)} types")

    # Product
    product_val = f.get("Custom.Product")
    if product_val:
        fields["customfield_11703"] = {"value": product_val}
        log_to_excel(wi_id, None, "Product", "Success", product_val)

    # Payment Integrity
    # CODE 1 DIFFERENCE — Code 1 does NOT map PaymentIntegrity (customfield_12599).
    # This is a User Story-specific field not present on Bug work items.
    payment_integrity = f.get("Custom.PaymentIntegrity")
    if payment_integrity:
        fields["customfield_12599"] = {"value": payment_integrity}
        log_to_excel(wi_id, None, "Payment Integrity", "Success", payment_integrity)

    # Cost Estimate (customfield_12457)
    # CODE 1 DIFFERENCE — Code 1 does NOT map CostEstimate (customfield_12457).
    # This is a User Story-specific estimation field not present on Bug work items.
    cost_estimate = f.get("Custom.CostEstimate")
    if cost_estimate:
        try:
            fields["customfield_12457"] = str(cost_estimate)
            log_to_excel(wi_id, None, "Cost Estimate", "Success", f"Value: {cost_estimate}")
        except Exception as e:
            log_to_excel(wi_id, None, "Cost Estimate", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Cost Estimate", "Skipped", "No Cost Estimate in ADO")

    # Policy Change
    # CODE 1 DIFFERENCE — Code 1 does NOT map PolicyChange (customfield_12600).
    # This is a User Story-specific boolean field not present on Bug work items.
    policy_change = f.get("Custom.PolicyChange")
    if policy_change is not None:
        mapped_value = "True" if policy_change else "False"
        fields["customfield_12600"] = {"value": mapped_value}
        log_to_excel(wi_id, None, "Policy Change", "Success", mapped_value)

    # Deliverable Type
    deliverable_type = f.get("Custom.DeliverableType")
    if deliverable_type:
        fields["customfield_11707"] = {"value": deliverable_type}
        log_to_excel(wi_id, None, "Deliverable Type", "Success", deliverable_type)

    # Risk Opened
    risk_opened = f.get("Custom.RiskOpened")
    if risk_opened is not None:
        mapped_value = "True" if risk_opened else "False"
        fields["customfield_11708"] = {
            "value": mapped_value
        }

    # New Data Table
    # CODE 1 DIFFERENCE — Code 1 does NOT map NewDataTable (customfield_12601).
    # This is a User Story-specific field not present on Bug work items.
    new_data_table = f.get("Custom.NewDataTable")
    if new_data_table:
        fields["customfield_12601"] = {"value": new_data_table}
        log_to_excel(wi_id, None, "New Data Table", "Success", new_data_table)

    # CODE 1 DIFFERENCE — Code 1 maps the following Bug-specific fields that do NOT appear
    # anywhere in this file (Code 2), because they only exist on Bug work items:
    #
    #   Custom.BugSeverity         → customfield_10090  (select: e.g. "Critical")
    #   Custom.BugPriority         → priority.name      (via BUG_PRIORITY_MAP: P1→Blocker etc.)
    #   Microsoft.VSTS.Common.ResolvedReason → resolution.name  (via RESOLUTION_MAP)
    #   Custom.BugArea             → customfield_11704  (select)
    #   Custom.BugType             → customfield_11705  (select)
    #   Custom.FoundbyAutomation   → customfield_11706  (select)
    #   Custom.BlockingType        → customfield_11699  (select)
    #   Microsoft.VSTS.Scheduling.OriginalEstimate  → customfield_11718 (float)
    #   Microsoft.VSTS.Scheduling.RemainingWork     → customfield_11719 (float)
    #   Microsoft.VSTS.Scheduling.CompletedWork     → customfield_11720 (float)
    #   Custom.EnvironmentFoundIn  → customfield_11715  (single select, in addition to multi-select 12597)
    #   Microsoft.VSTS.Build.FoundIn        → customfield_11713 (string)
    #   Microsoft.VSTS.Build.IntegrationBuild → customfield_11714 (string)
    #   Custom.BugFailureAnalysis           → customfield_12820 (select)
    #   Custom.BugUserAnalysisSubcategory   → customfield_12821 (select)
    #   Custom.QABugUserAnalysisSubcategory → customfield_12822 (select)
    #   Custom.RelatedUserStorywhereDefectwasIntroduced → customfield_12823 (select)
    #   Custom.Teamthebugisassociatedwith   → customfield_12824 (select)
    #   Custom.DeveloperwhoIntroducedDefect → customfield_12825 (string)
    #   Custom.QAwhooriginallytestedintroducedDefect → customfield_12826 (user picker)
    #   Custom.ReleasewhereBugwasintroduced → customfield_12859 (select)
    #   Custom.Whattypeofdefectisit         → customfield_12860 (select)
    #   Custom.IsthisDefectrelatedtoatestingissue → customfield_12861 (select)
    #   Custom.QABugUserAnalysisSubcategory → customfield_12862 (select, second mapping)
    #   Custom.ImpactedorAffectedApplicationbytheBug → customfield_12863 (select)
    #   Custom.QAwhointroduceddefect        → customfield_12864 (user picker)
    #   Custom.CYPRESS                      → customfield_12865 (select)
    #   Custom.TrendNotes                   → customfield_12866 (select)
    #   Custom.CTMS                         → customfield_12867 (select)
    #   Custom.QAComment                    → customfield_12868 (ADF doc)
    #   Custom.CTMSComment                  → customfield_12869 (ADF doc)
    #   Custom.TrendNotesComment            → customfield_12870 (ADF doc)
    #   Custom.ImplementationDate           → customfield_11755 (datetime)
    #   Custom.StatusDropdown               → customfield_11756 (select)
    #   Custom.CAPAuthor                    → customfield_11758 (user picker)
    #   Microsoft.VSTS.CMMI.CorrectiveActionPlan → customfield_11757 (ADF doc)

    # Risk Rank
    risk_rank_val = f.get("Custom.RiskRank")
    if risk_rank_val:
        fields["customfield_12876"] = {"value": risk_rank_val}
        log_to_excel(wi_id, None, "Risk Rank", "Success", risk_rank_val)

    # Team Lead
    team_lead = f.get("Custom.TeamLead")
    if team_lead:
        team_lead_email = None
        if isinstance(team_lead, dict):
            team_lead_email = team_lead.get("uniqueName") or team_lead.get("mail")
        elif isinstance(team_lead, str):
            team_lead_email = team_lead
        if team_lead_email:
            team_lead_account_id = get_jira_account_id_for_email(team_lead_email)
            if team_lead_account_id:
                fields["customfield_12712"] = {"id": team_lead_account_id}
                log_to_excel(wi_id, None, "Team Lead", "Success", team_lead_email)
            else:
                log_to_excel(wi_id, None, "Team Lead", "Failed", f"No mapping for: {team_lead_email}")

    # Risk Status
    risk_status_val = f.get("Custom.RiskStatus")
    if risk_status_val:
        fields["customfield_12877"] = {"value": risk_status_val}
        log_to_excel(wi_id, None, "Risk Status", "Success", risk_status_val)

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

    # Dev ETA
    dev_eta = f.get("Custom.DevETA")
    if dev_eta:
        try:
            fields["customfield_12709"] = convert_ado_datetime(dev_eta)
            log_to_excel(wi_id, None, "Dev ETA", "Success", f"Date: {dev_eta[:10]}")
        except Exception as e:
            log_to_excel(wi_id, None, "Dev ETA", "Failed", str(e)[:100])

    # Developer (User Picker)
    developer = f.get("Custom.Developer")
    if developer:
        developer_email = None
        if isinstance(developer, dict):
            developer_email = developer.get("uniqueName") or developer.get("mail")
        elif isinstance(developer, str):
            developer_email = developer
        if developer_email:
            developer_account_id = get_jira_account_id_for_email(developer_email)
            if developer_account_id:
                fields["customfield_12717"] = {"id": developer_account_id}
                log_to_excel(wi_id, None, "Developer", "Success", developer_email)
            else:
                log_to_excel(wi_id, None, "Developer", "Failed", f"MISSING MAPPING: {developer_email}")

    # QA Estimate (Number field)
    qa_estimate = f.get("Custom.QAEstimate")

    if qa_estimate is not None:
        try:
            fields["customfield_11967"] = float(qa_estimate)
            log_to_excel(wi_id, None, "QA Estimate", "Success", qa_estimate)
        except ValueError as e:
            log_to_excel(wi_id, None, "QA Estimate", "Failed", str(e)[:100])

    # QA (User Picker)
    qa = f.get("Custom.QA")
    if qa:
        qa_email = None
        if isinstance(qa, dict):
            qa_email = qa.get("uniqueName") or qa.get("mail")
        elif isinstance(qa, str):
            qa_email = qa
        if qa_email:
            qa_account_id = get_jira_account_id_for_email(qa_email)
            if qa_account_id:
                fields["customfield_12754"] = {"id": qa_account_id}
                log_to_excel(wi_id, None, "QA", "Success", qa_email)
            else:
                log_to_excel(wi_id, None, "QA", "Failed", f"MISSING MAPPING: {qa_email}")

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
            src = node.get("src", "").strip()
            if src:
                if src.startswith("data:"):
                    # Inline base64 image — decode and save locally
                    try:
                        import base64, uuid
                        header, b64data = src.split(",", 1)
                        # e.g. "data:image/jpeg;base64"
                        mime = header.split(":")[1].split(";")[0]  # e.g. "image/jpeg"
                        ext = mime.split("/")[1]  # e.g. "jpeg"
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


# CODE 1 DIFFERENCE — Code 1 replaces _parse_comment_markdown with a much more capable
# _parse_comment_markdown_improved function. Key additions in Code 1:
#
#   1. Calls _fix_ado_malformed_markdown_links(text) FIRST, which:
#        - Calls html.unescape() to decode HTML entities (including emoji) in the raw text
#        - Fixes "angle-bracket triple-link" pattern that ADO emits for URLs:
#            <[https://url>](https://url> "title")  →  [https://url](https://url)
#        - Fixes title-escaped links: [text](url "title")  →  [text](url)
#
#   2. Extracts inline images (![alt](url)) from the markdown text separately, preserving
#      their exact document position. Images are returned as {"kind": "image"} parts that
#      get downloaded from ADO and uploaded to Jira in process_comment_and_post().
#      Code 2's _parse_comment_markdown returns a single flat text part with no image extraction.
#
#   3. After image extraction, passes non-image text segments through _resolve_markdown_mentions
#      AND _convert_markdown_to_jira_wiki (the full version with headings/tables/lists/links).
#
#   4. Calls _deduplicate_links_in_parts(parts) after parsing to remove duplicate Jira-wiki
#      [text|url] links that ADO sometimes emits multiple times for the same URL.
#
# Code 2's _parse_comment_markdown does none of the above: it only resolves mentions and
# applies the two-regex bold/italic conversion, with no image extraction, no link fixing,
# and no deduplication.
IMAGE_MD_RE = re.compile(r'!\[[^\]]*\]\(([^)]+)\)')

def _parse_comment_markdown(text: str, mention_map: Dict[str, str]) -> List[Dict]:
    if not text:
        return []

    # Unescape HTML entities first (Code 1 difference)
    import html as html_lib
    text = html_lib.unescape(text)

    resolved_text = _resolve_markdown_mentions(text, mention_map)
    resolved_text = _convert_markdown_to_jira_wiki(resolved_text)

    parts: List[Dict] = []
    last_end = 0

    for m in IMAGE_MD_RE.finditer(resolved_text):
        # Text before the image
        before = resolved_text[last_end:m.start()].strip()
        if before:
            parts.append({"kind": "text", "value": before})
        # The image URL
        img_url = m.group(1).strip()
        parts.append({"kind": "image", "src": img_url})
        last_end = m.end()

    # Remaining text after last image
    after = resolved_text[last_end:].strip()
    if after:
        parts.append({"kind": "text", "value": after})

    if not parts and resolved_text.strip():
        parts.append({"kind": "text", "value": resolved_text.strip()})

    return parts

# CODE 1 DIFFERENCE — Code 1 has a more sophisticated process_comment_and_post that
# uses a separate detect_comment_format() helper function instead of the inline format
# detection logic used here. detect_comment_format() adds two extra heuristic checks:
#
#   1. _looks_like_block_html(raw_text): checks whether the raw 'text' field itself contains
#      block-level HTML tags (<div>, <img>, <br>, <p>, <table>, etc.). If so, it overrides
#      the format to "html" even when ADO reports format="markdown" or format="text".
#      This handles a known ADO quirk where the text field stores raw HTML but the format
#      field is wrong. Without this, the markdown parser receives raw HTML as literal text
#      and passes angle-brackets and tags through to the Jira comment unchanged.
#
#   2. It also checks rendered_text first — if rendered_text looks like HTML, it always
#      routes to the HTML parser to avoid duplicate links from the markdown pipeline.
#
# Code 2's inline detection only checks comment.get("format") and a simple HTML tag regex
# on rendered_text/raw_text, and can misroute ADO comments that have format="markdown"
# but contain raw HTML in the text field.
#
# Code 1 also uses build_comment_body_with_images() to assemble the final body,
# which applies re.sub(r'\n{3,}', '\n\n', txt) to normalise excessive blank lines
# inside each text part before joining — Code 2 does this only at the very end.
def process_comment_and_post(issue_key: str, comment: Dict, wi_id=None, comment_index: int = 0,
                              author: str = "Unknown", created_str: str = ""):
    meta_line = f"*Originally commented by {author} on {created_str}*"

    comment_format = comment.get("format", "html").lower()
    raw_text = comment.get("text", "")
    rendered_text = comment.get("renderedText", "")

    def _looks_like_html(text: str) -> bool:
        return bool(re.search(r'<[a-zA-Z][^>]*>', text or ""))

    if comment_format == "markdown":
        if not raw_text or not raw_text.strip():
            _post_text_comment(issue_key, meta_line, wi_id=wi_id, comment_index=comment_index)
            update_wi_row(wi_id, f"Comment[{comment_index}]", "Success", "Meta-only (empty markdown body)")
            return

        log(f"   🔍 Resolving mentions for comment {comment_index}...")
        mention_map = _build_mention_map_from_comment(comment)
        parts = _parse_comment_markdown(raw_text, mention_map)

    elif comment_format == "html" or _looks_like_html(rendered_text) or _looks_like_html(raw_text):
        html_content = rendered_text.strip() or raw_text.strip()
        if not html_content:
            _post_text_comment(issue_key, meta_line, wi_id=wi_id, comment_index=comment_index)
            update_wi_row(wi_id, f"Comment[{comment_index}]", "Success", "Meta-only (empty HTML body)")
            return
        parts = _parse_comment_html(html_content)

    else:
        if not raw_text or not raw_text.strip():
            _post_text_comment(issue_key, meta_line, wi_id=wi_id, comment_index=comment_index)
            update_wi_row(wi_id, f"Comment[{comment_index}]", "Success", "Meta-only (empty body)")
            return

        log(f"   🔍 Resolving mentions for comment {comment_index}...")
        mention_map = _build_mention_map_from_comment(comment)
        parts = _parse_comment_markdown(raw_text, mention_map)

    if not parts:
        _post_text_comment(issue_key, meta_line, wi_id=wi_id, comment_index=comment_index)
        update_wi_row(wi_id, f"Comment[{comment_index}]", "Success", "Meta-only (no parseable content)")
        return

    has_images = any(p["kind"] in ("image", "image_local") for p in parts)
    has_text = any(p["kind"] == "text" for p in parts)

    log(f"   💬 Comment[{comment_index}]: {len(parts)} parts | images={sum(1 for p in parts if p['kind'] == 'image')} | text={has_text}")

    if not has_images:
        full_text = "\n\n".join(p["value"] for p in parts if p["kind"] == "text").strip()
        body = f"{meta_line}\n\n{full_text}" if full_text else meta_line
        _post_text_comment(issue_key, body, wi_id=wi_id, comment_index=comment_index)
        update_wi_row(wi_id, f"Comment[{comment_index}]", "Success",
                      f"Text-only comment posted ({len(body)} chars)")
        return

    image_url_map: Dict[str, str] = {}
    img_upload_count = 0
    img_fail_count = 0

    for p in parts:
        if p["kind"] not in ("image", "image_local"):
            continue
        
        if p["kind"] == "image_local":
            local_file = p["path"]
            src_key = p["path"]  # use path as the dedup key
        else:
            src = p["src"]
            src_key = src
            if src_key in image_url_map:
                continue
            filename = parse_qs(urlparse(src).query or "").get("fileName", [f"image_{comment_index}.png"])[0]
            local_file = download_images_to_ado_attachments(src, wi_id=wi_id, issue_key=issue_key)
        
        if src_key in image_url_map:
            continue
            
        if not local_file:
            img_fail_count += 1
            image_url_map[src_key] = None
            continue
            
        upload_info = jira_upload_attachment(issue_key, local_file, wi_id=wi_id)
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

    body_parts: List[str] = [meta_line]
    for p in parts:
        if p["kind"] == "text":
            txt = p["value"].strip()
            if txt:
                body_parts.append(txt)
        elif p["kind"] in ("image", "image_local"):
            key = p.get("src") or p.get("path")
            jira_url = image_url_map.get(key)
            if jira_url:
                body_parts.append(f"!{jira_url}!")
            else:
                body_parts.append("[Image could not be loaded]")

    final_body = "\n\n".join(body_parts).strip()
    comment_url = f"{clean_base(JIRA_URL)}/rest/api/2/issue/{issue_key}/comment"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    r = api_request("post", comment_url, wi_id=wi_id, issue_key=issue_key,
                    step=f"Post Comment[{comment_index}]",
                    auth=jira_auth(), headers=headers, json={"body": final_body})
    if r.status_code in (200, 201):
        log(f"   ✅ Comment[{comment_index}] posted ({img_upload_count} images, {img_fail_count} failed)")
        update_wi_row(wi_id, f"Comment[{comment_index}]", "Success",
                      f"Posted: {img_upload_count} images OK, {img_fail_count} failed")
    else:
        log(f"   ❌ Comment[{comment_index}] post failed: {r.status_code} {r.text[:200]}")
        update_wi_row(wi_id, f"Comment[{comment_index}]", "Failed",
                      f"HTTP {r.status_code}: {r.text[:80]}")


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

    # CODE 1 DIFFERENCE — Code 1 queries for WorkItemType = 'Bug' and targets a date range
    # of 2026-02-21 to 2026-02-28 as a batch migration scope.
    # Code 2 queries for WorkItemType = 'User Story' over the same date range.
    # Both files are single-project migration scripts targeting different work item types.
    wiql = (
        "SELECT [System.Id] FROM WorkItems WHERE [System.CreatedDate] >= '2026-02-21' "
        "AND [System.CreatedDate] <= '2026-02-28' AND [System.WorkItemType] = 'User Story'"
    )
    ids = ado_wiql_all_ids(wiql)
    if not ids:
        log("No work items found.")
        return

    log(f"📌 Found {len(ids)} work items.")

    # CODE 1 DIFFERENCE — Code 1 sets SPECIFIC_ID = ["845200"] to target a single work item
    # for a focused test/debug run. Code 2 sets SPECIFIC_ID = None to process all found IDs.
    # Code 1 also sets MAX_TO_PROCESS = 1000 while Code 2 uses 10000.
    SPECIFIC_ID = ["877273"]

    if SPECIFIC_ID:
        ids = SPECIFIC_ID
        log(f"🎯 Running migration for specific work items: {SPECIFIC_ID}")
    else:
        START_INDEX = 0
        MAX_TO_PROCESS = 10000
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

            # CODE 1 DIFFERENCE — Code 1 runs steps 3 (ReproSteps) and 4 (TCM Steps) fully,
            # whereas Code 2 comments both sections out. Reasons:
            #
            # Step 3 (ReproSteps / customfield_12494):
            #   Bug work items carry Microsoft.VSTS.TCM.ReproSteps (HTML), which Code 1 processes:
            #     a) Calls fix_relative_urls_in_repro_steps() to convert /HESource/ relative URLs
            #        to absolute https://dev.azure.com URLs before any further processing.
            #     b) Calls download_and_upload_reprosteps_images() to download images from ADO
            #        and upload them to Jira, building an attachment_map of {src → jira_id}.
            #     c) Waits 2 seconds (time.sleep(2)) for Jira attachment processing.
            #     d) Verifies each uploaded attachment via GET /rest/api/3/attachment/{id}.
            #     e) Calls convert_ado_reprosteps_to_jira_adf() with the verified_map to produce
            #        a full ADF document preserving tables, lists, images, and code blocks.
            #     f) PUTs the ADF to customfield_12494 on the Jira issue.
            #   User Story work items do not have ReproSteps, so Code 2 skips this entirely.
            #
            # Step 4 (TCM Steps / customfield_10632):
            #   Bug work items carry Microsoft.VSTS.TCM.Steps (structured XML), which Code 1 converts
            #   into a Jira ADF table (Steps / Action / Expected result / Attachments columns) via
            #   steps_formatter() and PUTs to customfield_10632.
            #   User Story work items do not have TCM Steps, so Code 2 skips this entirely.

            # # 3) ReproSteps
            # repro_steps_html = wi.get("fields", {}).get("Microsoft.VSTS.TCM.ReproSteps", "")
            # if repro_steps_html:
            #     try:
            #         attachment_map = download_and_upload_reprosteps_images(
            #             issue_key, repro_steps_html, wi_id=wi_id)
            #         if attachment_map:
            #             time.sleep(2)
            #         verified_map = {}
            #         for src, att_id in attachment_map.items():
            #             base = clean_base(JIRA_URL)
            #             verify_url = f"{base}/rest/api/3/attachment/{att_id}"
            #             verify_response = api_request("get", verify_url, wi_id=wi_id, issue_key=issue_key,
            #                                            step=f"Verify Attachment {att_id}", auth=jira_auth())
            #             if verify_response.status_code == 200:
            #                 verified_map[src] = att_id
            #         jira_repro_adf = convert_ado_reprosteps_to_jira_adf(repro_steps_html, verified_map, issue_key)
            #         if jira_repro_adf.get("content"):
            #             base = clean_base(JIRA_URL)
            #             url = f"{base}/rest/api/3/issue/{issue_key}"
            #             r = api_request("put", url, wi_id=wi_id, issue_key=issue_key,
            #                             step="Update ReproSteps", auth=jira_auth(),
            #                             headers={"Content-Type": "application/json"},
            #                             json={"fields": {"customfield_12494": jira_repro_adf}})
            #             if r.status_code in (200, 204):
            #                 log(f"   ✅ Updated ReproSteps for {issue_key}")
            #                 log_to_excel(wi_id, issue_key, "Update ReproSteps", "Success", "ReproSteps updated")
            #             else:
            #                 log_to_excel(wi_id, issue_key, "Update ReproSteps", "Failed", f"HTTP {r.status_code}")
            #     except Exception as e:
            #         log_to_excel(wi_id, issue_key, "Update ReproSteps", "Error", str(e)[:100])
            # else:
            #     log_to_excel(wi_id, issue_key, "Update ReproSteps", "Skipped", "No ReproSteps found")

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

            # 5) Description — uses improved_process_description_to_adf for table support
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

            # 5b) Acceptance Criteria
            try:
                acceptance_criteria_html = wi.get("fields", {}).get("Microsoft.VSTS.Common.AcceptanceCriteria", "")
                if acceptance_criteria_html:
                    ac_adf = improved_process_description_to_adf(
                        issue_key, acceptance_criteria_html, wi_id=wi_id)
                    base = clean_base(JIRA_URL)
                    url = f"{base}/rest/api/3/issue/{issue_key}"
                    r = api_request("put", url, wi_id=wi_id, issue_key=issue_key,
                                    step="Update AcceptanceCriteria", auth=jira_auth(),
                                    headers={"Content-Type": "application/json"},
                                    json={"fields": {"customfield_11880": ac_adf}})
                    if r.status_code in (200, 204):
                        log_to_excel(wi_id, issue_key, "Update AcceptanceCriteria", "Success", "Acceptance Criteria updated")
                    else:
                        log_to_excel(wi_id, issue_key, "Update AcceptanceCriteria", "Failed", f"HTTP {r.status_code}")
                else:
                    log_to_excel(wi_id, issue_key, "Update AcceptanceCriteria", "Skipped", "No Acceptance Criteria")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Update AcceptanceCriteria", "Error", str(e)[:100])
                
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