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
    # "Bug": "Bug",
    # "Defect": "Defect",
    # "Epic": "Epic",
    # "Feature": "Feature",
    # "Hotfix": "Hotfix",
    # "Issue": "Issue",
    # "Joes Test": "Joes Test",
    # "Portfolio Epic": "Portfolio Epic",
    # "Post Lockdown": "Post Lockdown",
    # "Request": "Request",
    # "RIDA (disabled)": "RIDA (disabled)",
    # "Risk (disabled)": "Risk (disabled)",
    "Task": "Task",
    # "Test Case": "Epic",
    # "Test Plan": "Test Plan",
    # "Test Suite": "Test Suite",
    # "User Story": "Story"
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
    "New": "Backlog",
    # "In Refinement": "REFINEMENT",
    # "Ready": "Ready",
    # "Blocked": "Hold",
    "In Progress": "In Progress",
    # "Development Complete": "Review",
    # "In Test": "Testing",
    # "Test Complete": "Ready for Release",
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
    # steps = f.get("Microsoft.VSTS.TCM.Steps", " ")
    # if steps:
    #     try:
    #         steps_payload = steps_formatter(steps)
    #         log_to_excel(wi_id, None, "Steps Parsing", "Success", "Parsed test steps")
    #     except Exception as e:
    #         log_to_excel(wi_id, None, "Steps Parsing", "Failed", str(e)[:100])
    
    summary = f.get("System.Title", "No Title")
    raw_desc = f.get("System.Description", "")
    ado_type = f.get("System.WorkItemType", "Task")
    jira_issuetype = WORKITEM_TYPE_MAP.get(ado_type, "Task")
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

    # Activity
    activity_val = f.get("Microsoft.VSTS.Common.Activity")
    if activity_val:
        fields["customfield_11814"] = {"value": activity_val}
        log_to_excel(wi_id, None, "Activity", "Success", activity_val)

    # Assertions
    assertions_val = f.get("Custom.Assertions")

    if assertions_val is not None:
        try:
            clean_val = str(assertions_val).strip()
            # Remove thousands separators
            clean_val = clean_val.replace(",", "")
            fields["customfield_12634"] = float(clean_val)
            log_to_excel(wi_id, None, "Assertions", "Success", f"Value: {assertions_val}")
        except Exception as e:
            log_to_excel(wi_id, None, "Assertions", "Failed", str(e)[:100])

    # Original Estimate
    original_estimate = f.get("Microsoft.VSTS.Scheduling.OriginalEstimate")
    if original_estimate is not None:
        try:
            fields["customfield_11718"] = float(original_estimate)
            log_to_excel(wi_id, None, "Original Estimate", "Success", f"Value: {original_estimate}")
        except ValueError as e:
            log_to_excel(wi_id, None, "Original Estimate", "Failed", str(e)[:100])
    
    # Remaining Work
    remaining_work = f.get("Microsoft.VSTS.Scheduling.RemainingWork")
    if remaining_work is not None:
        try:
            fields["customfield_11719"] = float(remaining_work)
            log_to_excel(wi_id, None, "Remaining Work", "Success", f"Value: {remaining_work}")
        except ValueError as e:
            log_to_excel(wi_id, None, "Remaining Work", "Failed", str(e)[:100])
    
    # Completed Work
    completed_work = f.get("Microsoft.VSTS.Scheduling.CompletedWork")
    if completed_work is not None:
        try:
            fields["customfield_11720"] = float(completed_work)
            log_to_excel(wi_id, None, "Completed Work", "Success", f"Value: {completed_work}")
        except ValueError as e:
            log_to_excel(wi_id, None, "Completed Work", "Failed", str(e)[:100])

    # Integration Build
    integrated_in_build = f.get("Microsoft.VSTS.Build.IntegrationBuild")
    if integrated_in_build:
        fields["customfield_11714"] = str(integrated_in_build)
        log_to_excel(wi_id, None, "Integration Build", "Success", integrated_in_build)
           
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

    # Regression Claims Executed
    reg_claims_executed = f.get("Custom.RegressionClaimsExecuted")
    if reg_claims_executed is not None:
        try:
            clean_val = str(reg_claims_executed).strip().replace(",", "")
            fields["customfield_12635"] = float(clean_val)
            log_to_excel(wi_id, None, "Regression Claims Executed", "Success", f"Value: {reg_claims_executed}")
        except Exception as e:
            log_to_excel(wi_id, None, "Regression Claims Executed", "Failed", str(e)[:100])

    # Is Regulatory
    is_regulatory = f.get("Custom.IsRegulatory")
    if is_regulatory is not None:
        try:
            mapped_value = str(is_regulatory)  # Keep capitalized
            fields["customfield_12149"] = {"value": mapped_value}
            log_to_excel(wi_id, None, "Is Regulatory", "Success", mapped_value)
        except Exception as e:
            log_to_excel(wi_id, None, "Is Regulatory", "Failed", str(e)[:100])

    # Policy Change
    policy_change = f.get("Custom.PolicyChange")
    if policy_change is not None:
        try:
            mapped_value = str(policy_change)  # Converts False → "False"
            fields["customfield_12600"] = {"value": mapped_value}
            log_to_excel(wi_id, None, "Policy Change", "Success", mapped_value)
        except Exception as e:
            log_to_excel(wi_id, None, "Policy Change", "Failed", str(e)[:100])

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
        is_block = name in {"p", "div", "li", "ul", "ol",
                             "h1", "h2", "h3", "h4", "h5", "h6",
                             "blockquote", "table", "tr", "td", "th"}
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


def _parse_comment_markdown(text: str, mention_map: Dict[str, str]) -> List[Dict]:
    if not text:
        return []

    resolved_text = _resolve_markdown_mentions(text, mention_map)
    resolved_text = _convert_markdown_to_jira_wiki(resolved_text)
    resolved_text = resolved_text.strip()
    if resolved_text:
        return [{"kind": "text", "value": resolved_text}]
    return []


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

    has_images = any(p["kind"] == "image" for p in parts)
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
        if p["kind"] != "image":
            continue
        src = p["src"]
        if src in image_url_map:
            continue
        filename = parse_qs(urlparse(src).query or "").get("fileName", [f"image_{comment_index}.png"])[0]
        local_file = download_images_to_ado_attachments(src, wi_id=wi_id, issue_key=issue_key)
        if not local_file:
            img_fail_count += 1
            image_url_map[src] = None
            continue
        upload_info = jira_upload_attachment(issue_key, local_file, wi_id=wi_id)
        if upload_info and upload_info.get("content"):
            image_url_map[src] = upload_info["content"]
            img_upload_count += 1
        elif upload_info and upload_info.get("id"):
            base = clean_base(JIRA_URL)
            image_url_map[src] = f"{base}/rest/api/2/attachment/content/{upload_info['id']}"
            img_upload_count += 1
        else:
            img_fail_count += 1
            image_url_map[src] = None

    body_parts: List[str] = [meta_line]
    for p in parts:
        if p["kind"] == "text":
            txt = p["value"].strip()
            if txt:
                body_parts.append(txt)
        elif p["kind"] == "image":
            jira_url = image_url_map.get(p["src"])
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

    wiql = (
        "SELECT [System.Id] FROM WorkItems WHERE [System.CreatedDate] >= '2025-11-01' "
        "AND [System.CreatedDate] <= '2026-02-21' AND [System.WorkItemType] = 'Task'"
    )
    ids = ado_wiql_all_ids(wiql)
    if not ids:
        log("No work items found.")
        return

    log(f"📌 Found {len(ids)} work items.")

    SPECIFIC_ID = ["839892",
"839973",
"840279",
"840878",
"841076",
"841643",
"841644",
"841819",
"842014",
"842127",
"842140",
"842141",
"842405",
"842436",
"842685",
"842686",
"842699",
"843154",
"843180",
"843186",
"843577",
"843759",
"843822",
"843960",
"844009",
"844279",
"844445",
"844561",
"844638",
"844902",
"844903",
"845533",
"845534",
"845535",
"845832",
"845835",
"846096",
"846174",
"846254",
"846255",
"846257",
"846340",
"846431",
"846504",
"846505",
"846677",
"846841",
"846975",
"846979",
"846991",
"847266",
"847407",
"847619",
"847620",
"847622",
"847708",
"847709",
"847711",
"847740",
"847783",
"847791",
"847802",
"847972",
"848088",
"848144",
"848145",
"848165",
"848174",
"848449",
"848450",
"848758",
"848805",
"848806",
"848807",
"848836",
"848867",
"848950",
"848952",
"849289",
"849348",
"849349",
"849350",
"849430",
"849806",
"849873",
"849960",
"849961",
"849962",
"849963",
"850008",
"850480",
"850485",
"850678",
"850679",
"850680",
"850681",
"850695",
"850709",
"851132",
"851133",
"851165",
"851223",
"851318",
"851339",
"851441",
"851442",
"851609",
"852675",
"866369",
"866370",
"866371",
"866854",
"866951",
"866952",
"867034",
"867144",
"867197",
"867205",
"867206",
"867298",
"867300",
"867766",
"867767",
"867903",
"868027",
"868195",
"868202",
"868413",
"868431",
"868490",
"868491",
"868531",
"868637",
"868768",
"868778",
"868788",
"868813",
"869051",
"869054",
"869219",
"869220",
"869230",
"869321",
"869655",
"870009",
"870127",
"870621",
"870673",
"870835",
"872647",
"872648",
"872649",
"872650",
"872651",
"872652",
"872653",
"872654",
"872656",
"872657",
"872658",
"872663",
"872664",
"872665",
"872666",
"872667",
"872678",
"872679",
"872680",
"873072",
"873073",
"873074",
"873076",
"873077",
"873078",
"873087",
"873088",
"876980"]

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

            # 5) Description
            try:
                raw_desc = wi.get("fields", {}).get("System.Description", "")
                if raw_desc:
                    desc_adf = process_description_to_adf(issue_key, raw_desc, wi_id=wi_id)
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