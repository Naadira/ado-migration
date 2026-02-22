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
# -------------------
# CONFIGURATION
# -------------------

# Azure DevOps
ADO_ORG = os.getenv("ADO_ORG")
ADO_PROJECT = os.getenv("ADO_PROJECT")
ADO_PAT = os.getenv("ADO_PAT")

# Jira
JIRA_URL = os.getenv("JIRA_URL")
JIRA_EMAIL = os.getenv("JIRA_EMAIL")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY")

#User-Credentials
Email = os.getenv("EMAIL")
JIRA_ACCOUNT_ID = os.getenv("JIRA_ACCOUNT_ID")

# Work item type mapping (ADO -> Jira)
WORKITEM_TYPE_MAP = {
    "Feature": "Epic",
}

# Priority mapping (ADO int -> Jira priority name)
PRIORITY_MAP = {
    1: "Blocker",
    2: "High",
    3: "Low",
    4: "Trivial"
}

# ADO State -> Jira Status mapping
STATE_MAP = {
    "New": "New",
    "Defined": "REFINEMENT",
    "In Grooming": "REFINEMENT",
    "Ready": "Ready",
    "Committed": "Ready",
    "Closed": "Done",
    "Removed": "Cancelled",
    "In Progress": "In Progress",
    "On Hold": "Hold",
    "Delivered": "Done",
}

# ============================================================
# CSV-BASED USER MAP LOADING
# ============================================================

USER_MAP_FILE = "ado_jira_user_map.csv"


def _load_user_map(filepath: str) -> Dict[str, str]:
    """
    Load ADO email -> Jira accountId mappings from a CSV/TSV file.
    First column: ADO email, Second column: Jira accountId.
    Falls back to the hardcoded USER_MAP_FALLBACK if file not found.
    """
    result: Dict[str, str] = {}
    if not os.path.exists(filepath):
        print(f"⚠️  User map file not found: {filepath}. Using hardcoded fallback map.")
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
                # Skip header row (if first col doesn't look like an email)
                if row_num == 1 and "@" not in email:
                    continue
                if email and account_id:
                    result[email] = account_id
        print(f"✅ Loaded {len(result)} user mappings from {filepath}")
    except Exception as e:
        print(f"❌ Failed to load user map from {filepath}: {e}")
    return result


# Hardcoded fallback (used only if CSV file is not present)
USER_MAP_FALLBACK: Dict[str, str] = {
    "mike.gallo@burgessgroup.com": "712020:b318e45e-e536-4842-82b0-dca4fe8e7bc0",
    "bridget.smith@burgessgroup.com": "712020:c3197f80-91cc-4818-af43-f2e9d436ba10",
    "christine.carpino@burgessgroup.com": "712020:627088d6-f69f-4e54-bd79-fe5f2e608064",
    "karen.lee@burgessgroup.com": "6390bc7b9960988ef6c265f2",
    "sujaya.ghosh@burgessgroup.com": "712020:7f37d800-4819-40e2-ae84-ca6c2807cdbf",
    "eric.mackie@burgessgroup.com": "712020:8e47455f-8dad-4073-91d0-3aa619d6880c",
    "danielle.mushyakov@burgessgroup.com": "712020:af5ffa07-f610-4c7e-a881-05688be58dee",
    "shakti.singh@burgessgroup.com": "712020:dc5cf0e4-32d8-4ae4-bfb1-91575051662c",
    "priya.r@burgessgroup.com": "712020:4d9b4843-5ae3-46dc-b2a4-55f305d0b009",
    "chad.leonard@burgessgroup.com": "712020:6a132739-c91f-48e9-80f1-3ad45094ce9d",
    "usha.jagarlamudi@burgessgroup.com": "712020:58d0dd30-1dd3-45ef-b31f-2131b399bd11",
    "khusbu.rani@burgessgroup.com": "712020:770ec3b2-603a-496c-baac-b02685b80a25",
    "abhilash.singh@burgessgroup.com": "712020:80b2b552-f57b-4032-ae36-80eb094e917e",
    "savir.khan@burgessgroup.com": "712020:9642c991-5857-4db3-b273-35985ce6cb95",
    "joyshree.dutta@burgessgroup.com": "712020:8fa0d9d0-ac03-47a3-b710-1910a66bdafc",
    "sakthivel.thamban@burgessgroup.com": "712020:fe1ce9ec-a84a-4617-8718-f9817bb8d04d",
    "nitish.garg@burgessgroup.com": "712020:b87ab234-6578-4101-9f98-5a6e64bcd911",
    "colleen.paskert@burgessgroup.com": "712020:5193ac01-94c8-4687-a9b3-9c117f71993b",
    "gajalakshmi.rathnakumar@burgessgroup.com": "712020:89ac5365-da61-4113-8c23-9ed648053d8c",
    "lalitha.thirumala@burgessgroup.com": "632b6fa988ed2ebef979a7d2",
    "vipul.havale@burgessgroup.com": "712020:0334f868-baf0-4536-9802-79ed01c53433",
    "shahana.begum@burgessgroup.com": "712020:fea49ab4-b353-4955-af3f-ecc3d109b759",
    "alex.chuyasov@burgessgroup.com": "712020:c35609f9-9b00-4005-8564-56563e9f0a4e",
    "tatyana.vulikh@healthedge.com": "712020:dac07315-2746-410f-be3a-7fb84407b20d",
    "asikul.ansary@burgessgroup.com": "712020:91cbc742-e919-4711-8bba-3a9a228f95ec",
    "michael.ince@burgessgroup.com": "712020:55d2f18b-243e-4d68-8e0c-88a65741d4de",
    "savir.khan@healthedge.com": "712020:9642c991-5857-4db3-b273-35985ce6cb95",
    "vparikh@burgessgroup.com": "712020:5bd9a6fd-615d-4be9-a8c4-12361b46876b",
    "nicholas.howe@burgessgroup.com": "712020:8a92a45e-2695-4983-86ff-e5dd0839b86d",
    "davis.perkins@burgessgroup.com": "6303e3358474ff0a80ac2690",
    "siddappa.mavinahundi@burgessgroup.com": "712020:1c815819-7cdc-4683-8e00-593175dfd722",
    "shawn.kane@burgessgroup.com": "712020:80d74fac-9ef0-477d-a90b-1b9b6eef412c",
}

# Load from CSV first; fall back to hardcoded map if file missing
_csv_map = _load_user_map(USER_MAP_FILE)
USER_MAP: Dict[str, str] = _csv_map if _csv_map else USER_MAP_FALLBACK

# Paging and throttling
WIQL_PAGE_SIZE = 200
SLEEP_BETWEEN_CALLS = 0.2

# Retry settings
MAX_RETRIES = 5
RETRY_BACKOFF = 2

# Mapping persistence
MAPPING_FILE = "ado_jira_mapping.json"

# Temp storage for downloaded ADO attachments
ATTACH_DIR = "ado_attachments"

# Recognize ADO attachment URLs
ATTACH_URL_SUBSTR = "/_apis/wit/attachments/"


# ============================================================
# RETRY-AWARE API WRAPPER
# ============================================================

def api_request(method: str, url: str, wi_id=None, issue_key=None, step="API Call", **kwargs) -> requests.Response:
    """
    Wraps requests.<method> with automatic retry on 429 (rate-limit) and 5xx errors.
    """
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


# ---------- Utilities ----------
def ado_auth():
    return ("", ADO_PAT)

def jira_auth():
    return HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN)

def clean_base(url: str) -> str:
    return (url or "").rstrip("/")

def chunked(iterable, size):
    for i in range(0, len(iterable), size):
        yield iterable[i:i+size]

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
        result = dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        print(result, "with milliseconds")
        return result
    except ValueError:
        pass

    try:
        dt = datetime.strptime(ado_datetime_str, "%Y-%m-%dT%H:%M:%SZ")
        dt = dt.replace(tzinfo=timezone.utc)
        result = dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        print(result, "time")
        return result
    except ValueError:
        pass

    try:
        dt = datetime.strptime(ado_datetime_str, "%d/%m/%Y %H:%M")
        result = dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        print("date_time")
        return result
    except ValueError:
        pass

    try:
        dt = datetime.strptime(ado_datetime_str, "%d/%m/%Y")
        formatted = dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        print(formatted, "date_month_year")
        return formatted
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
    print(r.json().get("value", []), "Issue Detail from AzureDevops")
    return r.json().get("value", [])

def ado_get_comments(wi_id: int) -> List[Dict]:
    url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/workItems/{wi_id}/comments?api-version=7.0-preview.3"
    r = api_request("get", url, wi_id=wi_id, step="Fetch Comments", auth=ado_auth())
    if r.status_code == 200:
        return r.json().get("comments", [])
    else:
        log(f"   ⚠️ Comments fetch failed for {wi_id}: {r.status_code} {r.text}")
        return []

def ado_get_attachments_from_relations(wi: Dict) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for rel in (wi.get("relations") or []):
        if rel.get("rel") == "AttachedFile":
            url = rel.get("url")
            name = (rel.get("attributes") or {}).get("name") or "attachment"
            out.append((url, name))
    return out


IMG_SRC_RE = re.compile(r'(?is)<img[^>]+src=["\']([^"\']+)["\']')
HREF_RE    = re.compile(r'(?is)<a[^>]+href=["\']([^"\']+)["\']')

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

def ado_inline_attachments_from_description(wi: Dict) -> List[Tuple[str, str]]:
    f = wi.get("fields", {})
    raw_desc = f.get("System.Description") or ""
    out: List[Tuple[str, str]] = []
    for u in extract_inline_ado_urls(raw_desc):
        name = parse_qs(urlparse(u).query or "").get("fileName", ["embedded_image"])[0]
        out.append((u, name))
    return out

def ado_inline_attachments_from_comments(wi_id: int) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for c in ado_get_comments(wi_id):
        html_body = c.get("html") or c.get("renderedText") or ""
        if not html_body:
            continue
        for u in extract_inline_ado_urls(html_body):
            name = parse_qs(urlparse(u).query or "").get("fileName", ["inline_attachment"])[0]
            out.append((u, name))
    return out


# ---------- Attachment download/upload ----------
def _with_download_params(u: str, api_version: str = "7.0") -> str:
    p = urlparse(u)
    q = parse_qs(p.query)
    q = {k: v for k, v in q.items()}
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
                return local_path
            else:
                log(f"   ⚠️ Download attempt {idx} failed ({r.status_code}) for: {url_try}")
        except Exception as e:
            log(f"   ⚠️ Download attempt {idx} error for: {url_try} -> {e}")
    return ""

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

def jira_upload_attachment(issue_key: str, file_path: str, wi_id=None) -> dict:
    if not file_path or not os.path.exists(file_path):
        return None

    base = clean_base(JIRA_URL)
    url = f"{base}/rest/api/3/issue/{issue_key}/attachments"
    headers = {"X-Atlassian-Token": "no-check"}
    with open(file_path, "rb") as fh:
        files = {"file": (os.path.basename(file_path), fh, mimetypes.guess_type(file_path)[0] or "application/octet-stream")}
        r = api_request("post", url, wi_id=wi_id, issue_key=issue_key,
                        step=f"Upload Attachment ({os.path.basename(file_path)})",
                        headers=headers, auth=jira_auth(), files=files)

    try:
        payload = r.json()
    except Exception:
        payload = None

    log(f"Upload response ({r.status_code}): {json.dumps(payload, indent=2) if payload else r.text[:500]}")

    if r.status_code not in (200, 201):
        log(f"⚠️ Failed to upload {file_path} to {issue_key}: {r.status_code} {r.text}")
        return None

    if isinstance(payload, list) and len(payload) > 0:
        info = payload[0]
    elif isinstance(payload, dict):
        info = payload
    else:
        info = None

    if not info:
        log("⚠️ Unexpected upload response format.")
        return None

    log(f"The info attachment data {info}")
    media_id = info.get("mediaId") or info.get("mediaIdString")
    numeric_id = str(info.get("id")) if info.get("id") is not None else None
    filename = info.get("filename") or os.path.basename(file_path)
    content_url = info.get("content") or info.get("url") or None
    log(f"Media ID : {media_id} , id: {numeric_id} , filename :{filename} , Content : {content_url}")
    return {
        "mediaId": media_id,
        "id": numeric_id,
        "filename": filename,
        "content": content_url,
        "raw": info
    }


# ---------- Jira issue + comments ----------
def jira_create_issue(fields: Dict, wi_id=None) -> str:
    base = clean_base(JIRA_URL)
    url = f"{base}/rest/api/3/issue"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    print(fields, "lop")
    r = api_request("post", url, wi_id=wi_id, step="Create Issue",
                    auth=jira_auth(), headers=headers, json={"fields": fields})
    if r.status_code == 201:
        key = r.json().get("key")
        log(f"✅ Created {key}")
        return key
    else:
        log(f"❌ Issue create failed: {r.status_code} {r.text}")
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
        log(f"   ⚠️ Add comment failed: {r.status_code} {r.text}")


URL_PATTERN = re.compile(r'(https?://\S+)')

def convert_text_with_links(text: str):
    parts = []
    last_idx = 0
    for match in URL_PATTERN.finditer(text):
        url = match.group(1)
        start, end = match.span()
        if start > last_idx:
            parts.append({"type": "text", "text": text[last_idx:start]})
        parts.append({
            "type": "text",
            "text": url,
            "marks": [{"type": "link", "attrs": {"href": url}}]
        })
        last_idx = end
    if last_idx < len(text):
        parts.append({"type": "text", "text": text[last_idx:]})
    return parts


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
                        "width": 710,
                        "height": 163
                    }}]
                })
            elif upload and upload.get("content"):
                adf_content.append({"type": "paragraph", "content": [{
                    "type": "text",
                    "text": upload.get("filename") or "Attachment",
                    "marks": [{"type": "link", "attrs": {"href": upload["content"]}}]
                }]})
        elif src:
            adf_content.append({"type": "paragraph", "content": [{
                "type": "text",
                "text": src,
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


from bs4 import BeautifulSoup

def clean_html_steps(html_text):
    if not html_text:
        return ""
    return BeautifulSoup(html_text, "html.parser").get_text(separator=" ", strip=True)

def steps_formatter(xml_data):
    global steps_payload
    print(xml_data)
    if not xml_data or not xml_data.strip():
        print("No steps found in ADO work item.")
        return {}
    root = ET.fromstring(xml_data)
    seen_steps = set()
    step_no = 0
    jira_payload = {
        "fields": {
            "customfield_10632": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "table",
                        "attrs": {"isNumberColumnEnabled": False, "layout": "default"},
                        "content": [
                            {
                                "type": "tableRow",
                                "content": [
                                    {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Steps", "marks": [{"type": "strong"}]}]}]},
                                    {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Action", "marks": [{"type": "strong"}]}]}]},
                                    {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Expected result", "marks": [{"type": "strong"}]}]}]},
                                    {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Attachments", "marks": [{"type": "strong"}]}]}]},
                                ],
                            },
                        ],
                    }
                ],
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
        table_row = {
            "type": "tableRow",
            "content": [
                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": str(step_no)}]}]},
                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": action_text}]}]},
                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": expected_text or ' '}]}]},
                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": " "}]}]},
            ],
        }
        table_content.append(table_row)
    steps_payload = json.dumps(jira_payload, indent=2)
    print(steps_payload)
    return steps_payload


def download_and_upload_reprosteps_images(issue_key: str, repro_html: str, wi_id=None) -> Dict[str, str]:
    attachment_map = {}
    if not repro_html:
        return attachment_map
    soup = BeautifulSoup(repro_html, "html.parser")
    imgs = soup.find_all("img")
    for img in imgs:
        src = img.get("src")
        if src and ATTACH_URL_SUBSTR in src and src not in attachment_map:
            filename = parse_qs(urlparse(src).query or "").get("fileName", ["attachment.png"])[0]
            local_file = ado_download_attachment(src, filename, wi_id=wi_id, issue_key=issue_key)
            if not local_file:
                log(f"   ⚠️ Failed to download: {src}")
                continue
            upload_info = jira_upload_attachment(issue_key, local_file, wi_id=wi_id)
            if upload_info and upload_info.get("id"):
                attachment_map[src] = upload_info["id"]
                log(f"   ✅ Mapped: {filename} → Jira ID {upload_info['id']}")
            else:
                log(f"   ⚠️ Failed to upload: {filename}")
    return attachment_map


def convert_ado_reprosteps_to_jira_adf(html_input: str, attachment_map: Dict[str, str] = None, issue_key: str = None) -> Dict:
    if not html_input:
        return {"type": "doc", "version": 1, "content": []}
    soup = BeautifulSoup(html_input, "html.parser")
    doc_content: List = []
    attachment_map = attachment_map or {}

    def create_media_node(src: str, use_external_fallback: bool = True):
        if src in attachment_map:
            jira_id = attachment_map[src]
            base = clean_base(JIRA_URL)
            attachment_url = f"{base}/rest/api/3/attachment/content/{jira_id}"
            return {
                "type": "mediaSingle",
                "attrs": {"layout": "center"},
                "content": [{"type": "media", "attrs": {"type": "external", "url": attachment_url}}]
            }
        elif use_external_fallback:
            return {
                "type": "mediaSingle",
                "attrs": {"layout": "center"},
                "content": [{"type": "media", "attrs": {"type": "external", "url": src}}]
            }
        return None

    def process_text_content(element):
        para_content = []
        for child in element.children:
            if hasattr(child, 'name'):
                if child.name in ["b", "strong"]:
                    text = child.get_text(strip=True)
                    if text:
                        para_content.append({"type": "text", "text": text, "marks": [{"type": "strong"}]})
                elif child.name in ["i", "em"]:
                    text = child.get_text(strip=True)
                    if text:
                        para_content.append({"type": "text", "text": text, "marks": [{"type": "em"}]})
                elif child.name == "br":
                    para_content.append({"type": "hardBreak"})
                elif child.name in ["div", "span", "p"]:
                    text = child.get_text(strip=True)
                    if text:
                        para_content.append({"type": "text", "text": text})
                else:
                    text = child.get_text(strip=True)
                    if text:
                        para_content.append({"type": "text", "text": text})
            elif isinstance(child, str):
                text = child.strip()
                if text:
                    para_content.append({"type": "text", "text": text})
        return para_content

    tables = soup.find_all("table")
    for table in tables:
        rows = []
        for tr in table.find_all("tr"):
            cells = []
            for td in tr.find_all(["td", "th"]):
                cell_blocks = []
                for img in td.find_all("img"):
                    src = img.get("src")
                    if src:
                        media_node = create_media_node(src)
                        if media_node:
                            cell_blocks.append(media_node)
                    img.decompose()
                cell_text = td.get_text(" ", strip=True)
                if cell_text:
                    para_content = process_text_content(td)
                    if para_content:
                        cell_blocks.append({"type": "paragraph", "content": para_content})
                if not cell_blocks:
                    cell_blocks = [{"type": "paragraph", "content": []}]
                cell_type = "tableHeader" if td.name == "th" else "tableCell"
                cells.append({"type": cell_type, "content": cell_blocks})
            if cells:
                rows.append({"type": "tableRow", "content": cells})
        if rows:
            doc_content.append({"type": "table", "attrs": {"isNumberColumnEnabled": False, "layout": "default"}, "content": rows})
        table.decompose()

    if tables and doc_content:
        doc_content.append({"type": "rule"})

    remaining_elements = soup.find_all(["div", "p", "img"], recursive=False)
    if not remaining_elements:
        remaining_text = soup.get_text(" ", strip=True)
        if remaining_text:
            doc_content.append({"type": "paragraph", "content": [{"type": "text", "text": remaining_text}]})
    else:
        for element in remaining_elements:
            if element.name == "img":
                src = element.get("src")
                if src:
                    media_node = create_media_node(src)
                    if media_node:
                        doc_content.append(media_node)
                element.decompose()
                continue
            for img in element.find_all("img"):
                src = img.get("src")
                if src:
                    media_node = create_media_node(src)
                    if media_node:
                        doc_content.append(media_node)
                img.decompose()
            text = element.get_text(" ", strip=True)
            if text:
                para_content = process_text_content(element)
                if para_content:
                    doc_content.append({"type": "paragraph", "content": para_content})

    if not doc_content:
        doc_content = [{"type": "paragraph", "content": []}]

    return {"type": "doc", "version": 1, "content": doc_content}


def build_jira_fields_from_ado(wi: Dict) -> Dict:
    global steps_payload
    steps_payload = None

    f = wi.get("fields", {})
    wi_id = wi.get("id")

    steps = f.get("Microsoft.VSTS.TCM.Steps", " ")
    print(steps, "steps_field")
    if steps:
        try:
            steps_payload = steps_formatter(steps)
            log_to_excel(wi_id, None, "Steps Field", "Success", "Steps formatted successfully")
        except Exception as e:
            log_to_excel(wi_id, None, "Steps Field", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Steps Field", "Skipped", "No steps in ADO")

    summary = f.get("System.Title", "No Title")
    raw_desc = f.get("System.Description", "")
    desc_text = clean_html_to_text(raw_desc)

    ado_type = f.get("System.WorkItemType", "Task")
    jira_issuetype = WORKITEM_TYPE_MAP.get(ado_type, "Task")
    log_to_excel(wi_id, None, "Issue Type Mapping", "Success", f"ADO: {ado_type} → Jira: {jira_issuetype}")

    tags = f.get("System.Tags", "")
    labels: List[str] = []
    if tags:
        try:
            parts = re.split(r"[;,]", tags)
            labels = [p.strip().replace(" ", "-") for p in parts if p.strip()]
            log_to_excel(wi_id, None, "Labels", "Success", f"Mapped {len(labels)} labels")
        except Exception as e:
            log_to_excel(wi_id, None, "Labels", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Labels", "Skipped", "No tags in ADO")

    ado_priority_val = f.get("Microsoft.VSTS.Common.Priority")
    try:
        ado_priority_int = int(ado_priority_val) if ado_priority_val is not None else None
    except Exception:
        ado_priority_int = None

    jira_priority_name = PRIORITY_MAP.get(ado_priority_int or -1)

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

    if jira_priority_name:
        try:
            fields["priority"] = {"name": jira_priority_name}
            log_to_excel(wi_id, None, "Priority", "Success", f"ADO: {ado_priority_int} → Jira: {jira_priority_name}")
        except Exception as e:
            log_to_excel(wi_id, None, "Priority", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Priority", "Skipped", "No priority mapping")

    value_stream = f.get("Custom.ValueStream")
    if value_stream:
        try:
            fields["customfield_11702"] = {"value": value_stream}
            log_to_excel(wi_id, None, "Value Stream", "Success", f"Value: {value_stream}")
        except Exception as e:
            log_to_excel(wi_id, None, "Value Stream", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Value Stream", "Skipped", "No value stream in ADO")

    tshirt_size = f.get("Custom.TShirtSize")
    if tshirt_size:
        try:
            fields["customfield_11791"] = {"value": tshirt_size}
            log_to_excel(wi_id, None, "T-Shirt Size", "Success", f"Value: {tshirt_size}")
        except Exception as e:
            log_to_excel(wi_id, None, "T-Shirt Size", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "T-Shirt Size", "Skipped", "No t-shirt size in ADO")

    priority_rank = f.get("Custom.PriorityRank")
    if priority_rank is not None:
        try:
            fields["customfield_11700"] = float(priority_rank)
            log_to_excel(wi_id, None, "Priority Rank", "Success", f"Value: {priority_rank}")
        except ValueError:
            log_to_excel(wi_id, None, "Priority Rank", "Error", f"Invalid value: {priority_rank}")
    else:
        log_to_excel(wi_id, None, "Priority Rank", "Skipped", "No priority rank in ADO")

    created_date = f.get("System.CreatedDate")
    if created_date:
        try:
            fields["customfield_12527"] = convert_ado_datetime(created_date)
            log_to_excel(wi_id, None, "Created Date", "Success", f"Mapped: {created_date}")
        except Exception as e:
            log_to_excel(wi_id, None, "Created Date", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Created Date", "Skipped", "No created date in ADO")

    start_date = f.get("Microsoft.VSTS.Scheduling.StartDate")
    if start_date:
        try:
            fields["customfield_10015"] = convert_ado_datetime(start_date)
            log_to_excel(wi_id, None, "Start Date", "Success", f"Mapped: {start_date}")
        except Exception as e:
            log_to_excel(wi_id, None, "Start Date", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Start Date", "Skipped", "No start date in ADO")

    target_date = f.get("Microsoft.VSTS.Scheduling.TargetDate")
    if target_date:
        try:
            fields["duedate"] = convert_ado_datetime(target_date)
            log_to_excel(wi_id, None, "Due Date", "Success", f"Mapped: {target_date}")
        except Exception as e:
            log_to_excel(wi_id, None, "Due Date", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Due Date", "Skipped", "No target date in ADO")

    pre_prod_date = f.get("Custom.PreProdDate")
    if pre_prod_date:
        try:
            fields["customfield_12449"] = convert_ado_datetime(pre_prod_date)
            log_to_excel(wi_id, None, "Pre Prod Date", "Success", f"Mapped: {pre_prod_date}")
        except Exception as e:
            log_to_excel(wi_id, None, "Pre Prod Date", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Pre Prod Date", "Skipped", "No PreProdDate in ADO")

    billable = f.get("Custom.Billable")
    if billable:
        try:
            fields["customfield_12450"] = {"value": billable}
            log_to_excel(wi_id, None, "Billable", "Success", f"Value: {billable}")
        except Exception as e:
            log_to_excel(wi_id, None, "Billable", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Billable", "Skipped", "No Billable value in ADO")

    feature_type = f.get("Custom.FeatureType")
    if feature_type:
        try:
            fields["customfield_12451"] = {"value": feature_type}
            log_to_excel(wi_id, None, "Feature Type", "Success", f"Value: {feature_type}")
        except Exception as e:
            log_to_excel(wi_id, None, "Feature Type", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Feature Type", "Skipped", "No Feature Type in ADO")

    identified_area = f.get("Custom.IdentifiedArea")
    if identified_area:
        try:
            fields["customfield_12452"] = {"value": identified_area}
            log_to_excel(wi_id, None, "Identified Area", "Success", f"Value: {identified_area}")
        except Exception as e:
            log_to_excel(wi_id, None, "Identified Area", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Identified Area", "Skipped", "No Identified Area in ADO")

    criticality = f.get("Custom.Criticality")
    if criticality:
        try:
            fields["customfield_12453"] = {"value": criticality}
            log_to_excel(wi_id, None, "Criticality", "Success", f"Value: {criticality}")
        except Exception as e:
            log_to_excel(wi_id, None, "Criticality", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Criticality", "Skipped", "No Criticality in ADO")

    branch_name = f.get("Custom.BranchName")
    if branch_name:
        try:
            fields["customfield_11710"] = str(branch_name)
            log_to_excel(wi_id, None, "Branch Name", "Success", f"Value: {branch_name}")
        except Exception as e:
            log_to_excel(wi_id, None, "Branch Name", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Branch Name", "Skipped", "No branch name in ADO")

    environment_found_in = f.get("Custom.EnvironmentFoundIn")
    if environment_found_in:
        try:
            fields["customfield_11715"] = {"value": environment_found_in}
            log_to_excel(wi_id, None, "Environment Found In", "Success", f"Value: {environment_found_in}")
        except Exception as e:
            log_to_excel(wi_id, None, "Environment Found In", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Environment Found In", "Skipped", "No environment found in ADO")

    release = f.get("Custom.Release")
    if release:
        try:
            fields["customfield_11712"] = {"value": release}
            log_to_excel(wi_id, None, "Release", "Success", f"Value: {release}")
        except Exception as e:
            log_to_excel(wi_id, None, "Release", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Release", "Skipped", "No release in ADO")

    scope = f.get("Custom.Scope")
    if scope:
        try:
            fields["customfield_12454"] = {"value": scope}
            log_to_excel(wi_id, None, "Scope", "Success", f"Value: {scope}")
        except Exception as e:
            log_to_excel(wi_id, None, "Scope", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Scope", "Skipped", "No Scope in ADO")

    control_type = f.get("Custom.ControlType")
    if control_type:
        try:
            fields["customfield_12455"] = {"value": control_type}
            log_to_excel(wi_id, None, "Control Type", "Success", f"Value: {control_type}")
        except Exception as e:
            log_to_excel(wi_id, None, "Control Type", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Control Type", "Skipped", "No Control Type in ADO")

    original_estimate = f.get("Microsoft.VSTS.Scheduling.OriginalEstimate")
    if original_estimate is not None:
        try:
            fields["customfield_11718"] = float(original_estimate)
            log_to_excel(wi_id, None, "Original Estimate", "Success", f"Value: {original_estimate}")
        except ValueError:
            log_to_excel(wi_id, None, "Original Estimate", "Error", f"Invalid value: {original_estimate}")
    else:
        log_to_excel(wi_id, None, "Original Estimate", "Skipped", "No original estimate in ADO")

    remaining_work = f.get("Microsoft.VSTS.Scheduling.RemainingWork")
    if remaining_work is not None:
        try:
            fields["customfield_11719"] = float(remaining_work)
            log_to_excel(wi_id, None, "Remaining Work", "Success", f"Value: {remaining_work}")
        except ValueError:
            log_to_excel(wi_id, None, "Remaining Work", "Error", f"Invalid value: {remaining_work}")
    else:
        log_to_excel(wi_id, None, "Remaining Work", "Skipped", "No remaining work in ADO")

    completed_work = f.get("Microsoft.VSTS.Scheduling.CompletedWork")
    if completed_work is not None:
        try:
            fields["customfield_11720"] = float(completed_work)
            log_to_excel(wi_id, None, "Completed Work", "Success", f"Value: {completed_work}")
        except ValueError:
            log_to_excel(wi_id, None, "Completed Work", "Error", f"Invalid value: {completed_work}")
    else:
        log_to_excel(wi_id, None, "Completed Work", "Skipped", "No completed work in ADO")

    customer_name = f.get("Custom.CustomerName")
    if customer_name:
        try:
            parts = [c.strip() for c in customer_name.split(";") if c.strip()]
            fields["customfield_12350"] = [{"value": p} for p in parts]
            log_to_excel(wi_id, None, "Customer Name", "Success", f"Mapped {len(parts)} values")
        except Exception as e:
            log_to_excel(wi_id, None, "Customer Name", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Customer Name", "Skipped", "No customer name in ADO")

    provider_type = f.get("Custom.ProviderType")
    if provider_type:
        try:
            parts = [p.strip() for p in provider_type.split(";") if p.strip()]
            fields["customfield_12383"] = [{"value": p} for p in parts]
            log_to_excel(wi_id, None, "Provider Type", "Success", f"Mapped {len(parts)} values")
        except Exception as e:
            log_to_excel(wi_id, None, "Provider Type", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Provider Type", "Skipped", "No provider type in ADO")

    custom_status = f.get("Custom.Status")
    if custom_status:
        try:
            fields["customfield_11794"] = {"value": custom_status}
            log_to_excel(wi_id, None, "Custom Status", "Success", f"Value: {custom_status}")
        except Exception as e:
            log_to_excel(wi_id, None, "Custom Status", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Custom Status", "Skipped", "No custom status in ADO")

    change_order = f.get("Custom.ChangeOrder")
    if change_order:
        try:
            fields["customfield_12456"] = str(change_order)
            log_to_excel(wi_id, None, "Change Order", "Success", f"Value: {change_order}")
        except Exception as e:
            log_to_excel(wi_id, None, "Change Order", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Change Order", "Skipped", "No Change Order in ADO")

    cost_estimate = f.get("Custom.CostEstimate")
    if cost_estimate:
        try:
            fields["customfield_12457"] = str(cost_estimate)
            log_to_excel(wi_id, None, "Cost Estimate", "Success", f"Value: {cost_estimate}")
        except Exception as e:
            log_to_excel(wi_id, None, "Cost Estimate", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Cost Estimate", "Skipped", "No Cost Estimate in ADO")

    actual = f.get("Custom.Actual")
    if actual:
        try:
            fields["customfield_12458"] = str(actual)
            log_to_excel(wi_id, None, "Actual", "Success", f"Value: {actual}")
        except Exception as e:
            log_to_excel(wi_id, None, "Actual", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Actual", "Skipped", "No Actual value in ADO")

    client_due_date = f.get("Microsoft.VSTS.Scheduling.DueDate")
    if client_due_date:
        try:
            fields["customfield_12459"] = convert_ado_datetime(client_due_date)
            log_to_excel(wi_id, None, "Client Due Date", "Success", f"Value: {client_due_date}")
        except Exception as e:
            log_to_excel(wi_id, None, "Client Due Date", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Client Due Date", "Skipped", "No Client Due Date in ADO")

    # Assignee mapping
    account_id = get_jira_account_id_for_email(assignee_email)
    print(f"🔎 ADO assignee email: {assignee_email}")
    print(f"🔎 Jira accountId mapped: {account_id}")

    if account_id:
        try:
            fields["assignee"] = {"id": account_id}
            log_to_excel(wi_id, None, "Assignee", "Success", f"Email: {assignee_email} → ID: {account_id}")
        except Exception as e:
            log_to_excel(wi_id, None, "Assignee", "Error", str(e)[:100])
    else:
        if assignee_email:
            log_to_excel(wi_id, None, "Assignee", "Warning", f"No mapping for email: {assignee_email}")
        else:
            log_to_excel(wi_id, None, "Assignee", "Skipped", "No assignee in ADO")

    # Reporter mapping
    created_by = f.get("System.CreatedBy")
    reporter_email = None
    if isinstance(created_by, dict):
        reporter_email = created_by.get("uniqueName") or created_by.get("mail")
        if reporter_email and isinstance(reporter_email, str):
            reporter_email = reporter_email.lower().strip()
        else:
            reporter_email = None

    if reporter_email and reporter_email in USER_MAP:
        try:
            fields["reporter"] = {"id": USER_MAP[reporter_email]}
            log_to_excel(wi_id, None, "Reporter", "Success", f"Email: {reporter_email} → ID: {USER_MAP[reporter_email]}")
        except Exception as e:
            log_to_excel(wi_id, None, "Reporter", "Error", str(e)[:100])
    else:
        try:
            fields["reporter"] = {"id": JIRA_ACCOUNT_ID}
            if reporter_email:
                log_to_excel(wi_id, None, "Reporter", "Warning", f"No mapping for {reporter_email}, using default")
            else:
                log_to_excel(wi_id, None, "Reporter", "Info", "Using default reporter - no email found")
        except Exception as e:
            log_to_excel(wi_id, None, "Reporter", "Error", str(e)[:100])

    deliverable_type = f.get("Custom.DeliverableType")
    if deliverable_type:
        try:
            fields["customfield_11707"] = {"value": deliverable_type}
            log_to_excel(wi_id, None, "Deliverable Type", "Success", f"Value: {deliverable_type}")
        except Exception as e:
            log_to_excel(wi_id, None, "Deliverable Type", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Deliverable Type", "Skipped", "No deliverable type in ADO")

    content_team_solutioning_support = f.get("Custom.ContentTeamSolutioningSupport")
    if content_team_solutioning_support:
        try:
            fields["customfield_12460"] = {"value": content_team_solutioning_support}
            log_to_excel(wi_id, None, "Content Team Solutioning Support", "Success", f"Value: {content_team_solutioning_support}")
        except Exception as e:
            log_to_excel(wi_id, None, "Content Team Solutioning Support", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Content Team Solutioning Support", "Skipped", "No Content Team Solutioning Support in ADO")

    client_scope = f.get("Custom.ClientScope")
    if client_scope:
        try:
            fields["customfield_12461"] = {"value": client_scope}
            log_to_excel(wi_id, None, "Client Scope", "Success", f"Value: {client_scope}")
        except Exception as e:
            log_to_excel(wi_id, None, "Client Scope", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Client Scope", "Skipped", "No Client Scope in ADO")

    priority_level = f.get("Custom.PriorityLevel")
    if priority_level:
        try:
            fields["customfield_12317"] = {"value": priority_level}
            log_to_excel(wi_id, None, "Priority Level", "Success", f"Value: {priority_level}")
        except Exception as e:
            log_to_excel(wi_id, None, "Priority Level", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Priority Level", "Skipped", "No priority level in ADO")

    strategic_theme = f.get("Custom.StrategicTheme")
    if strategic_theme:
        try:
            fields["customfield_11796"] = {"value": strategic_theme}
            log_to_excel(wi_id, None, "Strategic Theme", "Success", f"Value: {strategic_theme}")
        except Exception as e:
            log_to_excel(wi_id, None, "Strategic Theme", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Strategic Theme", "Skipped", "No strategic theme in ADO")

    module_type = f.get("Custom.ModuleType")
    if module_type:
        try:
            fields["customfield_11797"] = [{"value": module_type}]
            log_to_excel(wi_id, None, "Module Type", "Success", f"Value: {module_type}")
        except Exception as e:
            log_to_excel(wi_id, None, "Module Type", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Module Type", "Skipped", "No module type in ADO")

    horizon = f.get("Custom.Horizon")
    if horizon:
        try:
            fields["customfield_11798"] = {"value": horizon}
            log_to_excel(wi_id, None, "Horizon", "Success", f"Value: {horizon}")
        except Exception as e:
            log_to_excel(wi_id, None, "Horizon", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Horizon", "Skipped", "No horizon in ADO")

    value_drivers = f.get("Custom.ValueDrivers")
    if value_drivers:
        try:
            fields["customfield_11799"] = {"value": value_drivers}
            log_to_excel(wi_id, None, "Value Drivers", "Success", f"Value: {value_drivers}")
        except Exception as e:
            log_to_excel(wi_id, None, "Value Drivers", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Value Drivers", "Skipped", "No value drivers in ADO")

    business_objective = f.get("Custom.BusinessObjectiveOKR")
    if business_objective:
        try:
            fields["customfield_11801"] = {"value": business_objective}
            log_to_excel(wi_id, None, "Business Objective", "Success", f"Value: {business_objective}")
        except Exception as e:
            log_to_excel(wi_id, None, "Business Objective", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Business Objective", "Skipped", "No business objective in ADO")

    team_dependency = f.get("Custom.TeamDependency")
    if team_dependency:
        try:
            parts = [p.strip() for p in team_dependency.split(";") if p.strip()]
            fields["customfield_11324"] = [{"value": p} for p in parts]
            log_to_excel(wi_id, None, "Team Dependency", "Success", f"Mapped {len(parts)} values")
        except Exception as e:
            log_to_excel(wi_id, None, "Team Dependency", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Team Dependency", "Skipped", "No team dependency in ADO")

    pi_values = f.get("Custom.PI")
    if pi_values:
        try:
            parts = [p.strip() for p in pi_values.split(";") if p.strip()]
            fields["customfield_11802"] = [{"value": p} for p in parts]
            log_to_excel(wi_id, None, "PI", "Success", f"Mapped {len(parts)} values")
        except Exception as e:
            log_to_excel(wi_id, None, "PI", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "PI", "Skipped", "No PI values in ADO")

    wid = f.get("System.Id")
    print(wid)
    if wid:
        try:
            ado_base = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}"
            ado_ui_link = f"{ado_base}/_workitems/edit/{wid}"
            fields["customfield_11600"] = ado_ui_link
            print("ADO WorkItem Link:", ado_ui_link)
            log_to_excel(wi_id, None, "ADO Work Item Link", "Success", f"Link: {ado_ui_link}")
        except Exception as e:
            log_to_excel(wi_id, None, "ADO Work Item Link", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "ADO Work Item Link", "Warning", "No System.Id found")

    area = f.get("System.AreaPath")
    if area:
        try:
            fields["customfield_11601"] = str(area)
            log_to_excel(wi_id, None, "Area Path", "Success", f"Value: {area}")
        except Exception as e:
            log_to_excel(wi_id, None, "Area Path", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Area Path", "Skipped", "No area path in ADO")

    iteration = f.get("System.IterationPath")
    if iteration:
        try:
            fields["customfield_11602"] = str(iteration)
            log_to_excel(wi_id, None, "Iteration Path", "Success", f"Value: {iteration}")
        except Exception as e:
            log_to_excel(wi_id, None, "Iteration Path", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Iteration Path", "Skipped", "No iteration path in ADO")

    reason = f.get("System.Reason")
    if reason:
        try:
            fields["customfield_11603"] = str(reason)
            log_to_excel(wi_id, None, "Reason", "Success", f"Value: {reason}")
        except Exception as e:
            log_to_excel(wi_id, None, "Reason", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Reason", "Skipped", "No reason in ADO")

    log_to_excel(wi_id, None, "Build Fields", "Completed", f"Built {len(fields)} fields successfully")
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
        log(f"⚠️ Failed to fetch transitions for {issue_key}")
        log_to_excel(wi_id, issue_key, "Transition", "Failed", f"Could not fetch transitions: {r.status_code}")
        return

    transitions = r.json().get("transitions", [])
    transition_id = None
    for t in transitions:
        if t["to"]["name"] == target_status:
            transition_id = t["id"]
            break

    if not transition_id:
        log(f"⚠️ No transition found from current status to '{target_status}' for {issue_key}")
        log_to_excel(wi_id, issue_key, "Transition", "Failed", f"No transition to {target_status}")
        return

    url = f"{base}/rest/api/3/issue/{issue_key}/transitions"
    payload = {"transition": {"id": transition_id}}
    r = api_request("post", url, wi_id=wi_id, issue_key=issue_key,
                    step=f"Transition to {target_status}",
                    auth=jira_auth(), headers={"Content-Type": "application/json"}, json=payload)
    if r.status_code in (200, 204):
        log(f"✅ {issue_key} transitioned to '{target_status}'")
        log_to_excel(wi_id, issue_key, "Transition", "Success", f"ADO: {ado_state} → Jira: {target_status}")
    else:
        log(f"⚠️ Failed to transition {issue_key} -> {target_status}: {r.status_code} {r.text}")
        log_to_excel(wi_id, issue_key, "Transition", "Failed", f"HTTP {r.status_code}")


def download_images_to_ado_attachments(url, wi_id=None, issue_key=None):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if "fileName" in query:
        filename = query["fileName"][0]
    else:
        filename = os.path.basename(parsed.path)
    output_file = os.path.join(OUTPUT_DIR, filename)
    response = api_request("get", url, wi_id=wi_id, issue_key=issue_key,
                            step=f"Download Image ({filename})",
                            auth=HTTPBasicAuth("", ADO_PAT), stream=True)
    if response.status_code == 200:
        with open(output_file, "wb") as f:
            for chunk in response.iter_content(1024):
                f.write(chunk)
        print(f"✅ Image downloaded as {output_file}")
        return output_file
    else:
        print(f"❌ Failed: {response.status_code} - {response.text}")
        return None


def jira_add_comment_for_link(issue_key: str, body: str, wi_id=None):
    url = f"{JIRA_URL}/rest/api/2/issue/{issue_key}/comment"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    response = api_request("post", url, wi_id=wi_id, issue_key=issue_key,
                           step="Add Comment (link)",
                           headers=headers, auth=jira_auth(), json={"body": body})
    if response.status_code == 201:
        print(f"✅ Comment added to {issue_key}")
    else:
        print(f"❌ Failed to add comment: {response.status_code}, {response.text}")


def clean_html_to_jira_format(issue_key: str, html_text: str, wi_id=None) -> str:
    if not html_text:
        return ""
    image_urls = re.findall(r'<img[^>]+src="([^"]+)"', html_text)
    html_text = html.unescape(html_text)
    html_text = re.sub(r"(?i)<br\s*/?>", "\n", html_text)

    if "<a" in html_text.lower():
        soup = BeautifulSoup(html_text, "html.parser")
        for a in soup.find_all("a"):
            href = a.get("href", "").strip()
            text = a.get_text(strip=True) or href
            if href:
                jira_link = f"[{text}|{href}]"
                a.replace_with(jira_link)
        clean_text = re.sub(r"<[^>]+>", " ", str(soup)).strip()
        if image_urls:
            print("Link with Image")
            for i in image_urls:
                local_file = download_images_to_ado_attachments(i, wi_id=wi_id, issue_key=issue_key)
                content_url = jira_upload_attachment(issue_key, local_file, wi_id=wi_id)
                jira_upload_attachment_as_comment(issue_key, content_url, clean_text, wi_id=wi_id)
        else:
            print("only Link")
            jira_add_comment_for_link(issue_key, clean_text, wi_id=wi_id)
        return " "
    else:
        return re.sub(r"<[^>]+>", " ", html_text).strip()


def ado_api_to_ui_link(api_url):
    match = re.search(r'/workItems/(\d+)', api_url)
    if not match:
        return api_url
    workitem_id = match.group(1)
    ui_url = re.sub(r'_apis/wit/workItems/\d+', f'_workitems/edit/{workitem_id}', api_url)
    return ui_url

def extract_wid(url):
    match = re.search(r'/workItems/(\d+)', url)
    return match.group(1) if match else None

def fetch_ado_workitem_title(wid):
    url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/workitems/{wid}?api-version=7.1"
    r = api_request("get", url, step=f"Fetch ADO Title ({wid})", auth=ado_auth())
    r.raise_for_status()
    data = r.json()
    title = data["fields"].get("System.Title", "ADO Work Item")
    wi_type = data["fields"].get("System.WorkItemType", "")
    return title, wi_type

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
# EXCEL TRACKING — SINGLE ROW PER WORK ITEM
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
    """Log a field's status into the work-item's single row."""
    key = _ensure_row(wi_id)
    safe_field = field.replace(" ", "_").replace("[", "").replace("]", "")
    wi_rows[key][f"{safe_field}_Status"] = status
    if value:
        wi_rows[key][f"{safe_field}_Message"] = str(value)[:300]
    print(f"  [{wi_id or 'SYS'}] {field} → {status} | {value}")


def set_wi_key(wi_id, issue_key: str):
    key = _ensure_row(wi_id)
    wi_rows[key]["Jira_IssueKey"] = issue_key


def set_wi_overall(wi_id, status: str):
    key = _ensure_row(wi_id)
    wi_rows[key]["Overall_Status"] = status


def log_system(event: str, status: str, message: str = ""):
    system_log.append({
        "Timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Event": event, "Status": status, "Message": message
    })
    print(f"[SYSTEM] {event} → {status} | {message}")


# Keep old migration_log list for backward compat
migration_log = []


def log_to_excel(wi_id, issue_key, step, status, message):
    """
    Central logging function — routes to per-row tracker AND keeps the old list.
    All fields for a work item accumulate in a single row in wi_rows.
    """
    migration_log.append({
        "WorkItemID": wi_id,
        "IssueKey": issue_key or "",
        "Step": step,
        "Status": status,
        "Message": message
    })
    print(f"{wi_id} | {issue_key or 'NA'} | {step} | {status} | {message}")

    if wi_id is None:
        log_system(step, status, message)
        return
    if issue_key:
        set_wi_key(wi_id, issue_key)
    update_wi_row(wi_id, step, status, message)


# ============================================================
# ADO IDENTITY LOOKUP — resolves GUIDs to display names
# (from Code 2)
# ============================================================

_ADO_IDENTITY_CACHE: Dict[str, str] = {}
_ADO_GUID_RE = re.compile(
    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
)


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


# ============================================================
# GUID MAP — ADO GUID -> Jira accountId
# (from Code 2)
# ============================================================

_ADO_GUID_MAP: Dict[str, str] = {}
_ADO_GUID_MAP_LOADED = False


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


def _get_ado_guid_map() -> Dict[str, str]:
    global _ADO_GUID_MAP, _ADO_GUID_MAP_LOADED
    if not _ADO_GUID_MAP_LOADED:
        _ADO_GUID_MAP = _build_ado_guid_to_jira_map()
        _ADO_GUID_MAP_LOADED = True
    return _ADO_GUID_MAP


# ============================================================
# MENTION RESOLUTION HELPERS
# (from Code 2)
# ============================================================

_MARKDOWN_MENTION_RE = re.compile(
    r'@<([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})>'
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
# IMPROVED COMMENT PARSER — handles markdown AND HTML formats
# (merged from Code 1 + Code 2)
# ============================================================

def _parse_comment_html(html_text: str) -> List[Dict]:
    """
    Parse ADO comment HTML into a list of parts: {"kind": "text"|"image", ...}
    Handles <a> mention links, regular links, inline images, <br>, block tags.
    """
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
                # Resolve mention to @Name or [~accountId:xxx]
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
            for child in node.children:
                walk(child)
            flush_text()
            return
        for child in node.children:
            walk(child)

    for top in soup.contents:
        walk(top)
    flush_text()
    return parts


def _parse_comment_markdown(text: str, mention_map: Dict[str, str]) -> List[Dict]:
    """Parse ADO markdown comment, resolving @mentions and converting to Jira wiki markup."""
    if not text:
        return []

    resolved_text = _resolve_markdown_mentions(text, mention_map)
    resolved_text = _convert_markdown_to_jira_wiki(resolved_text)
    resolved_text = resolved_text.strip()
    if resolved_text:
        return [{"kind": "text", "value": resolved_text}]
    return []


def _post_wiki_comment(issue_key: str, body: str, wi_id=None, comment_index: int = 0):
    """Post a Jira wiki-markup comment via REST API v2."""
    comment_url = f"{clean_base(JIRA_URL)}/rest/api/2/issue/{issue_key}/comment"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    r = api_request("post", comment_url, wi_id=wi_id, issue_key=issue_key,
                    step=f"Post Comment[{comment_index}]",
                    auth=jira_auth(), headers=headers, json={"body": body})
    if r.status_code not in (200, 201):
        log(f"   ❌ Comment[{comment_index}] post failed: {r.status_code} {r.text[:200]}")
        log_to_excel(wi_id, issue_key, f"Comment[{comment_index}]", "Failed",
                     f"HTTP {r.status_code}: {r.text[:80]}")


def process_comment_and_post(issue_key: str, comment: Dict, wi_id=None,
                              comment_index: int = 0, author: str = "Unknown",
                              created_str: str = ""):
    """
    Parse a single ADO comment and post it to Jira.

    Handles ALL combinations and formats:
      - HTML format: text-only, image-only, text+image(s), images interspersed with text,
        mention links (@person), regular hyperlinks
      - Markdown format: @<GUID> mentions resolved via ADO Identity API or ado_guid_map.csv,
        markdown bold/italic converted to Jira wiki markup
      - Multiple consecutive images
      - Empty comments (posts meta-line only)

    Images are downloaded from ADO, uploaded to Jira, then embedded as !url! in wiki markup.
    """
    meta_line = f"*Originally commented by {author} on {created_str}*"

    comment_format = comment.get("format", "html").lower()
    raw_text = comment.get("text", "")
    rendered_text = comment.get("renderedText", "")

    def _looks_like_html(text: str) -> bool:
        return bool(re.search(r'<[a-zA-Z][^>]*>', text or ""))

    # ---- Determine format and parse accordingly ----
    if comment_format == "markdown":
        if not raw_text or not raw_text.strip():
            _post_wiki_comment(issue_key, meta_line, wi_id=wi_id, comment_index=comment_index)
            log_to_excel(wi_id, issue_key, f"Comment[{comment_index}]", "Success",
                         "Meta-only (empty markdown body)")
            return

        log(f"   🔍 Resolving mentions for comment {comment_index}...")
        mention_map = _build_mention_map_from_comment(comment)
        parts = _parse_comment_markdown(raw_text, mention_map)

    elif comment_format == "html" or _looks_like_html(rendered_text) or _looks_like_html(raw_text):
        html_content = rendered_text.strip() or raw_text.strip()
        if not html_content:
            _post_wiki_comment(issue_key, meta_line, wi_id=wi_id, comment_index=comment_index)
            log_to_excel(wi_id, issue_key, f"Comment[{comment_index}]", "Success",
                         "Meta-only (empty HTML body)")
            return
        parts = _parse_comment_html(html_content)

    else:
        # Fallback: treat as plain text / markdown
        if not raw_text or not raw_text.strip():
            _post_wiki_comment(issue_key, meta_line, wi_id=wi_id, comment_index=comment_index)
            log_to_excel(wi_id, issue_key, f"Comment[{comment_index}]", "Success",
                         "Meta-only (empty body)")
            return

        log(f"   🔍 Resolving mentions for comment {comment_index}...")
        mention_map = _build_mention_map_from_comment(comment)
        parts = _parse_comment_markdown(raw_text, mention_map)

    if not parts:
        _post_wiki_comment(issue_key, meta_line, wi_id=wi_id, comment_index=comment_index)
        log_to_excel(wi_id, issue_key, f"Comment[{comment_index}]", "Success",
                     "Meta-only (no parseable content)")
        return

    has_images = any(p["kind"] == "image" for p in parts)
    has_text = any(p["kind"] == "text" for p in parts)

    log(f"   💬 Comment[{comment_index}]: {len(parts)} parts | "
        f"images={sum(1 for p in parts if p['kind'] == 'image')} | "
        f"text={has_text}")

    # ---- Case: text only (no images) ----
    if not has_images:
        full_text = "\n\n".join(p["value"] for p in parts if p["kind"] == "text").strip()
        body = f"{meta_line}\n\n{full_text}" if full_text else meta_line
        _post_wiki_comment(issue_key, body, wi_id=wi_id, comment_index=comment_index)
        log_to_excel(wi_id, issue_key, f"Comment[{comment_index}]", "Success",
                     f"Text-only ({len(body)} chars)")
        return

    # ---- Cases with images: upload all images first, then build combined body ----
    image_url_map: Dict[str, str] = {}  # ADO src -> Jira content URL
    img_upload_ok = 0
    img_upload_fail = 0

    for p in parts:
        if p["kind"] != "image":
            continue
        src = p["src"]
        if src in image_url_map:
            continue  # already processed
        filename = parse_qs(urlparse(src).query or "").get("fileName", [f"img_{comment_index}.png"])[0]
        local_file = download_images_to_ado_attachments(src, wi_id=wi_id, issue_key=issue_key)
        if not local_file:
            img_upload_fail += 1
            image_url_map[src] = None
            log(f"   ⚠️ Failed to download image: {src}")
            continue
        upload_info = jira_upload_attachment(issue_key, local_file, wi_id=wi_id)
        if upload_info and upload_info.get("content"):
            image_url_map[src] = upload_info["content"]
            img_upload_ok += 1
        elif upload_info and upload_info.get("id"):
            base = clean_base(JIRA_URL)
            image_url_map[src] = f"{base}/rest/api/2/attachment/content/{upload_info['id']}"
            img_upload_ok += 1
        else:
            img_upload_fail += 1
            image_url_map[src] = None
            log(f"   ⚠️ Failed to upload image: {filename}")

    # Build combined wiki-markup body, preserving original order of text/image parts
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

    # Post single comment with everything combined
    comment_url = f"{clean_base(JIRA_URL)}/rest/api/2/issue/{issue_key}/comment"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    r = api_request("post", comment_url, wi_id=wi_id, issue_key=issue_key,
                    step=f"Post Comment[{comment_index}]",
                    auth=jira_auth(), headers=headers, json={"body": final_body})

    if r.status_code in (200, 201):
        log(f"   ✅ Comment[{comment_index}] posted ({img_upload_ok} images OK, {img_upload_fail} failed)")
        log_to_excel(wi_id, issue_key, f"Comment[{comment_index}]", "Success",
                     f"Posted: {img_upload_ok} images OK, {img_upload_fail} failed")
    else:
        log(f"   ❌ Comment[{comment_index}] post failed: {r.status_code} {r.text[:200]}")
        log_to_excel(wi_id, issue_key, f"Comment[{comment_index}]", "Failed",
                     f"HTTP {r.status_code}: {r.text[:80]}")


def migrate_all():
    ensure_dir(ATTACH_DIR)

    if os.path.exists(MAPPING_FILE):
        with open(MAPPING_FILE, "r") as f:
            mapping = json.load(f)
    else:
        mapping = {}

    wiql = (
        "SELECT [System.Id] FROM WorkItems WHERE [System.CreatedDate] >= '2025-11-01' "
        "AND [System.CreatedDate] <= '2026-02-21' AND [System.WorkItemType] = 'Feature'"
    )
    ids = ado_wiql_all_ids(wiql)
    if not ids:
        log("No work items found.")
        return

    log(f"📌 Found {len(ids)} work items.")

    SPECIFIC_ID = None  # Set to None for batch mode

    if SPECIFIC_ID:
        ids = SPECIFIC_ID
        log(f"🎯 Running migration for a single work item: {SPECIFIC_ID}")
    else:
        START_INDEX = 0
        MAX_TO_PROCESS = 1000
        ids = ids[START_INDEX:START_INDEX + MAX_TO_PROCESS]
        log(f"📌 Processing {len(ids)} work items (from index {START_INDEX}) in this run.")

    for batch in chunked(ids, WIQL_PAGE_SIZE):
        time.sleep(SLEEP_BETWEEN_CALLS)
        workitems = ado_get_workitems_by_ids(batch)
        workitems.sort(key=lambda w: w.get("id", 0))
        log(f"➡️  Processing batch of {len(workitems)}")

        for wi in workitems:
            print(wi, "This is the work Item")
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
                if issue_key:
                    log_to_excel(wi_id, issue_key, "Create Issue", "Success", f"Issue {issue_key} created successfully")
                else:
                    log_to_excel(wi_id, None, "Create Issue", "Failed", "Issue creation returned None")
                    continue
            except Exception as e:
                log_to_excel(wi_id, None, "Create Issue", "Error", str(e)[:100])
                continue

            # 2) CREATE LINKS
            try:
                create_links_from_ado(wi, issue_key, wi_id=wi_id)
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Create Links", "Error", str(e)[:100])

            # 3) UPDATE DESCRIPTION FIELD
            try:
                print("one")
                raw_desc = wi.get("fields", {}).get("System.Description", "")
                print(raw_desc, "test")
                if raw_desc:
                    print("two")
                    log_to_excel(wi_id, issue_key, "Description", "Processing", "Processing description with images")
                    desc_adf = process_description_to_adf(issue_key, raw_desc, wi_id=wi_id)
                    base = clean_base(JIRA_URL)
                    url = f"{base}/rest/api/3/issue/{issue_key}"
                    payload = {"fields": {"description": desc_adf}}
                    headers = {"Content-Type": "application/json"}
                    r = api_request("put", url, wi_id=wi_id, issue_key=issue_key,
                                    step="Update Description", auth=jira_auth(),
                                    headers=headers, json=payload)
                    print(r.status_code, "test123")
                    if r.status_code in (200, 204):
                        log(f"✅ Updated description for {issue_key} with inline images")
                        log_to_excel(wi_id, issue_key, "Update Description", "Success", "Description updated successfully")
                    else:
                        log(f"⚠️ Failed to update description for {issue_key}: {r.status_code} {r.text}")
                        log_to_excel(wi_id, issue_key, "Update Description", "Failed", f"{r.status_code} {r.text[:100]}")
                else:
                    log_to_excel(wi_id, issue_key, "Description", "Skipped", "No description in ADO")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Update Description", "Error", str(e)[:100])

            if not issue_key:
                continue

            # Save mapping ASAP
            mapping[wi_id_str] = issue_key
            with open(MAPPING_FILE, "w") as f:
                json.dump(mapping, f, indent=2)

            # 4) Transition to mapped status
            try:
                ado_state = wi.get("fields", {}).get("System.State", "New")
                jira_transition_issue(issue_key, ado_state, wi_id=wi_id)
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Transition", "Error", str(e)[:100])

            # 5) ATTACHMENTS MIGRATION
            try:
                relations = wi.get("relations", [])
                attachments_to_upload = [
                    (rel.get("url"), rel.get("attributes", {}).get("name", "attachment"))
                    for rel in relations
                    if rel.get("rel") == "AttachedFile" and rel.get("url")
                ]
                if attachments_to_upload:
                    log(f"   📎 Processing {len(attachments_to_upload)} attachment(s) for {issue_key}")
                    log_to_excel(wi_id, issue_key, "Attachments", "Processing", f"Found {len(attachments_to_upload)} attachments")
                    for att_url, att_filename in attachments_to_upload:
                        try:
                            local_path = ado_download_attachment(att_url, att_filename, wi_id=wi_id, issue_key=issue_key)
                            if local_path and os.path.exists(local_path):
                                upload_result = jira_upload_attachment(issue_key, local_path, wi_id=wi_id)
                                if upload_result and upload_result.get("id"):
                                    log(f"   ✅ Uploaded attachment: {att_filename}")
                                    log_to_excel(wi_id, issue_key, "Upload Attachment", "Success", f"Uploaded {att_filename}")
                                else:
                                    log(f"   ⚠️ Failed to upload: {att_filename}")
                                    log_to_excel(wi_id, issue_key, "Upload Attachment", "Failed", f"Upload failed for {att_filename}")
                                try:
                                    os.remove(local_path)
                                except Exception:
                                    pass
                            else:
                                log(f"   ⚠️ Download failed for: {att_filename}")
                                log_to_excel(wi_id, issue_key, "Download Attachment", "Failed", f"Download failed for {att_filename}")
                        except Exception as e:
                            log(f"   ❌ Error processing attachment {att_filename}: {e}")
                            log_to_excel(wi_id, issue_key, "Process Attachment", "Error", str(e)[:100])
                    log(f"   ✅ Attachment processing complete for {issue_key}")
                else:
                    log(f"   ℹ️ No attachments found for {issue_key}")
                    log_to_excel(wi_id, issue_key, "Attachments", "Skipped", "No attachments in ADO")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Attachments", "Error", str(e)[:100])

            # 6) COMMENTS — improved handler covers all text/image/markdown combinations
            try:
                comments = ado_get_comments(wi_id)
                if comments:
                    log_to_excel(wi_id, issue_key, "Comments_Total", "Info", str(len(comments)))
                    ok_count = 0
                    fail_count = 0
                    for idx, c in enumerate(reversed(comments)):
                        author = (c.get("createdBy") or {}).get("displayName", "Unknown")
                        created_date = c.get("createdDate", "")
                        try:
                            dt = datetime.strptime(created_date, "%Y-%m-%dT%H:%M:%S.%fZ")
                            created_str = dt.strftime("%d %b %Y at %H:%M")
                        except Exception:
                            created_str = created_date

                        log(f"   💬 Processing comment {idx + 1}/{len(comments)} by {author} on {created_str}")
                        try:
                            process_comment_and_post(
                                issue_key, c,
                                wi_id=wi_id,
                                comment_index=idx + 1,
                                author=author,
                                created_str=created_str
                            )
                            ok_count += 1
                        except Exception as e:
                            log(f"   ❌ Comment {idx + 1} failed: {e}")
                            log_to_excel(wi_id, issue_key, f"Comment[{idx + 1}]", "Error", str(e)[:100])
                            fail_count += 1

                    log_to_excel(wi_id, issue_key, "Comments_Summary", "Complete",
                                 f"{ok_count} OK, {fail_count} failed of {len(comments)}")
                else:
                    log_to_excel(wi_id, issue_key, "Comments_Total", "Skipped", "No comments in ADO")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Comments", "Error", str(e)[:100])

            set_wi_overall(wi_id, "Complete")
            log(f"✅ Work item ADO #{wi_id_str} → {issue_key} migration complete")

    log("🎉 Migration completed.")

    # Cleanup
    try:
        for file in os.listdir("ado_attachments"):
            try:
                os.remove(os.path.join("ado_attachments", file))
            except Exception as e:
                print(f"Failed to delete {file}: {e}")
    except Exception as e:
        print(f"Failed to cleanup attachments directory: {e}")

    # ============================================================
    # SAVE EXCEL — one row per work item
    # Each work item's field statuses are all in a single row.
    # ============================================================
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
                # Auto-size columns
                ws = writer.sheets["WorkItems"]
                for col_cells in ws.columns:
                    max_len = max((len(str(c.value or "")) for c in col_cells), default=10)
                    ws.column_dimensions[col_cells[0].column_letter].width = min(max_len + 4, 60)

            print("✅ Migration log saved to migration_log.xlsx (one row per work item)")
        else:
            print("⚠️ No work item rows to save.")
    except Exception as e:
        print(f"❌ Failed to save migration_log.xlsx: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    migrate_all()