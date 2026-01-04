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
Email=os.getenv("EMAIL")
JIRA_ACCOUNT_ID=os.getenv("JIRA_ACCOUNT_ID")
# print("iop",JIRA_ACCOUNT_ID,Email)
# Work item type mapping (ADO -> Jira)
WORKITEM_TYPE_MAP = {
    "Bug": "Bug",
    "Defect": "Defect",
    "Epic": "Initiative",
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
    "User Story": "User Story"
}

# Priority mapping (ADO int -> Jira priority name)
PRIORITY_MAP = {
    1: "Blocker",
    2: "High",
    3: "Low",
    4: "Trivial"
}

# BUG_PRIORITY_MAP = {
#     "P1": "Blocker",
#     "P2": "High",
#     "P3": "Low",
#     "P4": "Trivial",
# }

# RESOLUTION_MAP = {
#     "As Designed": "Working As Expected",
#     "Cannot Reproduce": "Cannot Reproduce",
#     "Copied to Backlog": "Copied to Backlog",
#     "Deferred": "Deferred",
#     "Duplicate": "Duplicate",
#     "Fixed": "Done",
#     "Fixed and verified": "Done",
#     "Obsolete": "Known Error",
#     "Will not Fix": "Won't Do"
# }


# ADO State -> Jira Status mapping
STATE_MAP = {
    "New": "New",
    # "Under Investigation": "In Refinement",
    # "Ready": "Ready",
    # "In Development": "In Progress",
    # "Development Complete": "Review",
    # "In Test": "Testing",
    # "Test Complete": "Ready to Release",
    # "Resolved": "Resolved",
    "Closed": "Done",
    # "Removed": "Cancelled",
    # "Waiting for customer": "Waiting for customer"
    "In Progress": "Building"
    # "Defined": "Defined",
    # "In Grooming": "In Grooming",
    # "On Hold": "On Hold",
    # "Delivered": "Delivered",
    # "Committed": "Committed",
    # "Active": "Active",
    # "Cancelled": "Cancelled",
    # "Submitted": "Submitted",
    # "Accepted": "Accepted",
    # "Denied": "Denied",
    # "Completed": "Completed",
    # "External Response Needed": "External Response Needed",
    # "External Response Provided": "External Response Provided",
    # "Cost Estimate Needed": "Cost Estimate Needed",
    # "Cost Estimate Provided": "Cost Estimate Provided",
    # "Internal Response Provided": "Internal Response Provided",
    # "Approved": "Approved",
    # "Ready for Scheduling": "Ready for Scheduling",
    # "Implementing": "Implementing",
    # "Design": "Design",
    # "Blocked": "Blocked",
    # "Inactive": "Inactive",
    # "In Planning": "In Planning",
    # "In Refinement": "In Refinement"
}


# # Optional (Not Configured yet): ADO email -> Jira accountId map
# USER_MAP: Dict[str, str] = {
#         Email:JIRA_ACCOUNT_ID,

# }

USER_MAP: Dict[str, str] = {
    "carl.anderson@burgessgroup.com":"712020:b78ee02e-70eb-4f25-99ea-6345b6b4fe62",
    "eric.mackie@burgessgroup.com": "712020:8e47455f-8dad-4073-91d0-3aa619d6880c",
    "Jay.Ramachandra@burgessgroup.com":"712020:c335b49a-cc31-4d97-be5e-eac21eb848b2",
    "nohjay.nimpson@burgessgroup.com":"712020:f9828523-eaf9-4db1-b914-c450b17fed47",
    "bridget.smith@burgessgroup.com":"712020:c3197f80-91cc-4818-af43-f2e9d436ba10",
    "lakshmi.ramamurthy@burgessgroup.com":"712020:d65756f3-27ac-424a-8aa4-dbf049c749d0",
    "michael.jelen@burgessgroup.com": "712020:74721f06-5356-43c5-b208-ad625554f6ca",
}

# Paging and throttling
WIQL_PAGE_SIZE = 200
SLEEP_BETWEEN_CALLS = 0.2

# Mapping persistence
MAPPING_FILE = "ado_jira_mapping.json"

# Temp storage for downloaded ADO attachments
ATTACH_DIR = "ado_attachments"

# Recognize ADO attachment URLs
ATTACH_URL_SUBSTR = "/_apis/wit/attachments/"


# ---------- Utilities ----------
def ado_auth():
    # ADO basic auth: username can be empty; PAT as password
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
    """Make a safe filename (Windows/macOS/Linux)."""
    if not name:
        return "attachment"
    # strip directories
    name = os.path.basename(name)
    # remove illegal/reserved characters
    name = re.sub(r'[\\/:*?"<>|]+', "_", name)
    # trim whitespace and dots
    name = name.strip().strip(".")
    if not name:
        name = "attachment"
    return name

def unique_path(root_dir: str, filename: str) -> str:
    """Return a non-colliding path by adding (1), (2), ... suffix if needed."""
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
    s = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n", s)      # <br> -> newline
    s = re.sub(r"(?i)</\s*p\s*>", "\n\n", s)         # </p> -> blank line
    s = re.sub(r"(?i)<\s*p\s*>", "", s)              # <p> opening removed
    s = re.sub(r"<[^>]+>", "", s)                    # strip remaining tags
    s = re.sub(r"\n{3,}", "\n\n", s)                 # collapse 3+ LFs
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
    # return USER_MAP.get(email, "")
    return USER_MAP.get(email.lower(), None)
    print(f"🔎 ADO assignee email: {assignee_email}")
    print(f"🔎 Jira accountId mapped: {account_id}")

# def convert_ado_datetime(ado_datetime_str):
#     if not ado_datetime_str:
#         return None
#     try:
#         # Parse ISO 8601 with timezone awareness (e.g., 2025-09-24T10:00:00Z)
#         dt = datetime.strptime(ado_datetime_str, "%Y-%m-%dT%H:%M:%SZ")
#         dt = dt.replace(tzinfo=timezone.utc)  # explicitly set UTC
#         result=dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
#         print(result,"time")
#         return result
#     except ValueError:
#         pass
#     try:
#         # Parse DD/MM/YYYY HH:MM
#         dt = datetime.strptime(ado_datetime_str, "%d/%m/%Y %H:%M")
#         result=dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
#         print("date_time")
#         return result
#     except ValueError:
#         pass
#     try:
#         # Parse DD/MM/YYYY
#         dt = datetime.strptime(ado_datetime_str, "%d/%m/%Y")
#         formatted = dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
#         print(formatted,"date_month_year")  # ✅ print actual value
#         return formatted
#     except ValueError:
#         return None

def convert_ado_datetime(ado_datetime_str):
    if not ado_datetime_str:
        return None

    # SUPPORT for milliseconds: 2025-12-03T07:03:18.42Z
    try:
        dt = datetime.strptime(ado_datetime_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        dt = dt.replace(tzinfo=timezone.utc)
        result = dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        print(result, "with milliseconds")
        return result
    except ValueError:
        pass

    # ISO 8601 without milliseconds
    try:
        dt = datetime.strptime(ado_datetime_str, "%Y-%m-%dT%H:%M:%SZ")
        dt = dt.replace(tzinfo=timezone.utc)
        result = dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        print(result, "time")
        return result
    except ValueError:
        pass

    # DD/MM/YYYY HH:MM
    try:
        dt = datetime.strptime(ado_datetime_str, "%d/%m/%Y %H:%M")
        result = dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        print("date_time")
        return result
    except ValueError:
        pass

    # DD/MM/YYYY
    try:
        dt = datetime.strptime(ado_datetime_str, "%d/%m/%Y")
        formatted = dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        print(formatted, "date_month_year")
        return formatted
    except ValueError:
        return None

# def convert_ado_datetime(ado_datetime_str):
#     if not ado_datetime_str:
#         return None
#     try:
#         # Try ISO 8601 first (ADO default)
#         dt = datetime.strptime(ado_datetime_str, "%Y-%m-%dT%H:%M:%SZ")
#         return dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
#     except ValueError:
#         pass
#     try:
#         # Try DD/MM/YYYY HH:MM
#         dt = datetime.strptime(ado_datetime_str, "%d/%m/%Y %H:%M")
#         return dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
#     except ValueError:
#         pass
#     try:
#         # Try DD/MM/YYYY
#         dt = datetime.strptime(ado_datetime_str, "%d/%m/%Y")
#         return dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
#     except ValueError:
#         return None



# ---------- ADO fetch ----------
def ado_wiql_all_ids(query: str) -> List[int]:
    print(query,"")
    url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/wiql?api-version=7.1-preview.2"
    r = requests.post(url, json={"query": query}, auth=ado_auth())

    # 🔽 ADD THIS
    print("Status:", r.status_code)
    print("Response text:", r.text[:500])  # show first 500 chars only


    r.raise_for_status()
    items = r.json().get("workItems", [])
    return [wi["id"] for wi in items]

def ado_get_workitems_by_ids(ids: List[int]) -> List[Dict]:
    if not ids:
        return []
    url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/workitems?api-version=7.0&$expand=all&ids={','.join(map(str, ids))}"
    r = requests.get(url, auth=ado_auth())
    r.raise_for_status()
    print(r.json().get("value", []),"Issue Detail from AzureDevops")
    return r.json().get("value", [])

    # 🔹 Debug print (only first 1–2 items to avoid spam)
    for wi in data[:2]:
        log(json.dumps(wi["fields"], indent=2))

    return data

def ado_get_comments(wi_id: int) -> List[Dict]:
    url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/workItems/{wi_id}/comments?api-version=7.0-preview.3"
    r = requests.get(url, auth=ado_auth())
    if r.status_code == 200:
        return r.json().get("comments", [])
    else:
        log(f"   ⚠️ Comments fetch failed for {wi_id}: {r.status_code} {r.text}")
        return []

def ado_get_attachments_from_relations(wi: Dict) -> List[Tuple[str, str]]:
    """
    Return list of (url, filename) for relations attachments.
    """
    out: List[Tuple[str, str]] = []
    for rel in (wi.get("relations") or []):
        if rel.get("rel") == "AttachedFile":
            url = rel.get("url")
            name = (rel.get("attributes") or {}).get("name") or "attachment"
            out.append((url, name))
    return out


# --- Inline attachments parsing (description + comments) ---
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
    # keep order but dedupe
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
            # sometimes only 'text' exists; skip as there are no inline images
            continue
        for u in extract_inline_ado_urls(html_body):
            name = parse_qs(urlparse(u).query or "").get("fileName", ["inline_attachment"])[0]
            out.append((u, name))
    return out


# ---------- Attachment download/upload ----------
def _with_download_params(u: str, api_version: str = "7.0") -> str:
    """
    Normalize ADO attachment URLs:
      - ensure api-version
      - prefer download=true to force stream content
    """
    p = urlparse(u)
    q = parse_qs(p.query)
    q = {k: v for k, v in q.items()}  # copy
    if "api-version" not in q:
        q["api-version"] = [api_version]
    if "download" not in q:
        q["download"] = ["true"]
    new_q = urlencode({k: v[0] if isinstance(v, list) and len(v) == 1 else v for k, v in q.items()}, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))

def ado_download_attachment(att_url: str, desired_filename: str) -> str:
    """
    Try multiple ways to fetch the binary. Return local file path or "".
    """
    ensure_dir(ATTACH_DIR)
    # sanitize & pick a unique path
    local_path = unique_path(ATTACH_DIR, desired_filename)

    # Try a couple of URL variants (7.0 then 6.0, with and without explicit download=true)
    candidates = [
        _with_download_params(att_url, "7.0"),
        _with_download_params(att_url, "6.0"),
        # bare URL as last resort
        att_url
    ]

    headers = {"Accept": "application/octet-stream"}
    for idx, url_try in enumerate(candidates, 1):
        try:
            r = requests.get(url_try, auth=ado_auth(), headers=headers, stream=True, allow_redirects=True)
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

def jira_upload_attachment_as_comment(issue_key,url_content,data):
    if (data==" "):
        base = clean_base(JIRA_URL)
        url=f"{base}/rest/api/2/issue/{issue_key}/comment"
        data={
    "body":f"!{url_content.get("content")}!"
}

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        r = requests.post(url, auth=jira_auth(), headers=headers,json=data)
        if r.status_code in (200, 201):
            log(f"Uploaded attachment as comment")
        else:
            log(f"   ⚠️ Upload attachment failed")
    else:
        base = clean_base(JIRA_URL)
        url=f"{base}/rest/api/2/issue/{issue_key}/comment"
        data={
    "body":f"{data} !{url_content.get("content")}!"
    }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        r = requests.post(url, auth=jira_auth(), headers=headers,json=data)
        if r.status_code in (200, 201):
            log(f"Uploaded attachment as comment")
        else:
            log(f"   ⚠️ Upload attachment failed")

def jira_upload_attachment(issue_key: str, file_path: str) -> dict:
    """
    Upload file to Jira and return a dict with keys:
      - mediaId (preferred, uuid string) OR None
      - id (numeric attachment id, as string) OR None
      - filename
      - content (direct content URL)
      - raw (original JSON response for debugging)
    """
    if not file_path or not os.path.exists(file_path):
        return None

    base = clean_base(JIRA_URL)
    url = f"{base}/rest/api/3/issue/{issue_key}/attachments"
    headers = {"X-Atlassian-Token": "no-check"}
    with open(file_path, "rb") as fh:
        files = {"file": (os.path.basename(file_path), fh, mimetypes.guess_type(file_path)[0] or "application/octet-stream")}
        r = requests.post(url, headers=headers, auth=jira_auth(), files=files)

    try:
        payload = r.json()
    except Exception:
        payload = None

    # Log response for debugging — remove or reduce in production
    log(f"Upload response ({r.status_code}): {json.dumps(payload, indent=2) if payload else r.text[:500]}")

    if r.status_code not in (200, 201):
        log(f"⚠️ Failed to upload {file_path} to {issue_key}: {r.status_code} {r.text}")
        return None

    # API returns an array of uploaded attachments; take first element
    if isinstance(payload, list) and len(payload) > 0:
        info = payload[0]
    elif isinstance(payload, dict):
        info = payload
    else:
        info = None

    if not info:
        log("⚠️ Unexpected upload response format.")
        return None
    log(f"The info attachement data {info}")
    # Common fields returned: id (numeric), filename, content (url), thumbnail, maybe mediaId
    media_id = info.get("mediaId") or info.get("mediaIdString")  # try common variants
    numeric_id = str(info.get("id")) if info.get("id") is not None else None
    filename = info.get("filename") or os.path.basename(file_path)
    content_url = info.get("content") or info.get("url") or None
    log(f"Meadia ID : {media_id} , id: {numeric_id} , filename :{filename} , Content : {content_url}, Raw : {info}")
    return {
        "mediaId": media_id,      # prefer this for embedding in ADF
        "id": numeric_id,         # numeric id (fallback / for reference)
        "filename": filename,
        "content": content_url,
        "raw": info
    }

# ---------- Jira issue + comments ----------
def jira_create_issue(fields: Dict) -> str:
    base = clean_base(JIRA_URL)
    url = f"{base}/rest/api/3/issue"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    print(fields,"lop")
    r = requests.post(url, auth=jira_auth(), headers=headers, json={"fields": fields})
    if r.status_code == 201:
        key = r.json().get("key")
        log(f"✅ Created {key}")
        print(steps_payload,"iop")
        return key
    else:
        log(f"❌ Issue create failed: {r.status_code} {r.text}")
        return ""

def jira_add_comment(issue_key: str, text: str):
    if not text:
        return
    base = clean_base(JIRA_URL)
    url = f"{base}/rest/api/3/issue/{issue_key}/comment"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    payload = {"body": to_adf_doc(text)}
    # payload={"body":text}
    r = requests.post(url, auth=jira_auth(), headers=headers, json=payload)
    if r.status_code not in (200, 201):
        log(f"   ⚠️ Add comment failed: {r.status_code} {r.text}")


# Regex to detect bare URLs
URL_PATTERN = re.compile(r'(https?://\S+)')

def convert_text_with_links(text: str):
    """
    Split plain text into ADF parts.
    Turns bare URLs into clickable Jira ADF links.
    """
    parts = []
    last_idx = 0
    for match in URL_PATTERN.finditer(text):
        url = match.group(1)
        start, end = match.span()

        # text before the URL
        if start > last_idx:
            parts.append({"type": "text", "text": text[last_idx:start]})

        # the URL itself as a link
        parts.append({
            "type": "text",
            "text": url,
            "marks": [{"type": "link", "attrs": {"href": url}}]
        })

        last_idx = end

    # any remaining text after the last URL
    if last_idx < len(text):
        parts.append({"type": "text", "text": text[last_idx:]})

    return parts


def process_description_to_adf(issue_key: str, raw_html: str) -> dict:
    """
    Convert ADO description HTML -> Jira ADF (supports text, links, images).
    Inline images are downloaded, uploaded to Jira, and embedded into description
    using mediaId when available. If mediaId missing, falls back to a link paragraph.
    """
    if not raw_html:
        return {"type": "doc", "version": 1, "content": []}

    soup = BeautifulSoup(raw_html, "html.parser")
    adf_content = []
    seen_links: set[str] = set()   # ✅ Track seen links

    # Use find_all on common block-level/nested tags (p, div, br, a, img)
    # We'll handle text in div/p and single-line breaks.
    # Normalize: replace <br> with newline so get_text handles it.
    for br in soup.find_all("br"):
        br.replace_with("\n")

    # Process block-level elements in document order
    for element in soup.find_all(["div", "p", "a", "img"], recursive=False ):
        print(f"\n👉 Processing element: <{element.name}> {str(element)[:80]}...")

        # If it's a div or p, it may contain nested a/img; handle its children
        if element.name in ("div", "p"):
            # If element contains images or links, iterate children to preserve order
            has_child_images = element.find("img")
            if has_child_images:
                for child in element.children:
                    if getattr(child, "name", None) == "img":
                        src = child.get("src")
                        print(f"  🖼 Found child <img> src={src}")
                        if src and ATTACH_URL_SUBSTR in src:
                            filename = parse_qs(urlparse(src).query or "").get("fileName", ["embedded.png"])[0]
                            local_file = download_images_to_ado_attachments(src)
                            if not local_file:
                                continue
                            upload = jira_upload_attachment(issue_key, local_file)
                            # log("Upload Data from the des attachment : ", upload," Asdfg")
                            if not upload:
                                continue
                            # prefer mediaId for embedding
                            if upload.get("id"):
                                adf_content.append(
                                {
                                    "type": "mediaSingle",
                                    "content": [
                                        {
                                        "type": "media",
                                        "attrs": {
                                            "type": "external",
                                            "url": f"{JIRA_URL}/rest/api/2/attachment/content/{upload.get("id")}",
                                            "width": 710,
                                            "height": 163
                                        }
                                        }
                                    ]
                                    }
                                )
                            else:
                                # fallback: insert clickable link to content
                                adf_content.append({
                                    "type": "paragraph",
                                    "content": [{
                                        "type": "text",
                                        "text": upload.get("filename") or "Attachment",
                                        "marks": [{"type": "link", "attrs": {"href": upload.get("content")}}] if upload.get("content") else []
                                    }]
                                })
                    elif getattr(child, "name", None) == "a":
    # skip here, will be handled in anchor section
                            continue
                    else:
                        text = getattr(child, "get_text", lambda strip=True: str(child))(strip=True)
                        if text:
                            print(f"  ✏️ Text inside <p/div>: {text}")
                            adf_content.append({"type": "paragraph", "content": [{"type": "text", "text": text}]})
            else:
                # No images inside — may contain plain text or links
                if element.find("a"):
                    block_content = []
                    for child in element.children:
                        if getattr(child, "name", None) == "a":
                            href = child.get("href", "").strip()
                            label = child.get_text(strip=True) or href
                            if href:
                                block_content.append({
                                    "type": "text",
                                    "text": label,
                                    "marks": [{"type": "link", "attrs": {"href": href}}]
                                })
                        elif isinstance(child, NavigableString) and child.strip():
                             block_content.extend(convert_text_with_links(str(child).strip()))
                    if block_content:
                        adf_content.append({
                            "type": "paragraph",
                            "content": block_content
                        })
                else:
                    # ✅ Only plain text (no links)
                    text = element.get_text("\n", strip=True).strip()
                    if text:
                        print(f"  ✏️ Plain text block: {text}")
                        adf_content.append({
                            "type": "paragraph",
                            "content": convert_text_with_links(text)
                        })

        elif element.name == "a":
            href = element.get("href", "").strip()
            label = element.get_text(strip=True) or href
            if href:   # ✅ avoid duplicates
                # seen_links.add(href)
                adf_content.append({
                    "type": "paragraph",
                    "content": [
                        {
                            "type": "text",
                            "text": label,
                            "marks": [{"type": "link", "attrs": {"href": href}}]
                        }
                    ]
                })

        elif element.name == "img":
            src = element.get("src")
            upload = {}
            if src and ATTACH_URL_SUBSTR in src:
                filename = parse_qs(urlparse(src).query or "").get("fileName", ["embedded.png"])[0]

                local_file = download_images_to_ado_attachments(src)
                if not local_file:
                    continue

                upload = jira_upload_attachment(issue_key, local_file)
                if not upload or not upload.get("id"):
                    continue

                # ✅ Only embed the media, no extra text
                adf_content.append(
                    {
                    "type": "mediaSingle",
                    "content": [
                        {
                        "type": "media",
                        "attrs": {
                            "type": "external",
                            "url": f"{JIRA_URL}/rest/api/2/attachment/content/{upload.get("id")}",
                            "width": 710,
                            "height": 163
                        }
                        }
                    ]
                    }
                )

            else:
                # fallback to clickable link to attachment
                adf_content.append({
                    "type": "paragraph",
                    "content": [{
                        "type": "text",
                        "text": upload.get("filename") or "Attachment",
                        "marks": [{"type": "link", "attrs": {"href": upload.get("content")}}] if upload.get("content") else []
                    }]
                })

    # If nothing was extracted, as safe fallback put plain text of raw_html
    if not adf_content:
        fallback_text = re.sub(r"<[^>]+>", " ", raw_html)
        fallback_text = html.unescape(fallback_text).strip()
        if fallback_text:
            adf_content = [{"type": "paragraph", "content": convert_text_with_links(fallback_text)}]

    # ✅ Debug print final ADF before returning
    import json
    print("\n📄 Final ADF Description:")
    print(json.dumps({"type": "doc", "version": 1, "content": adf_content}, indent=2))


    return {"type": "doc", "version": 1, "content": adf_content}

def process_description_to_adf(issue_key: str, raw_html: str) -> dict:
    """
    Convert ADO description HTML -> Jira ADF (supports text, links, images).
    Preserves document order: text/link parts remain inline, images become mediaSingle blocks in place.
    """
    if not raw_html:
        return {"type": "doc", "version": 1, "content": []}

    soup = BeautifulSoup(raw_html, "html.parser")

    # normalize <br> into newline characters
    # for br in soup.find_all("br"):
    #     br.replace_with("\n")

    adf_content = []
    seen_links: set[str] = set()
    block_tags = {"p", "div", "li", "blockquote", "h1", "h2", "h3", "h4", "h5", "h6"}

    def flush_paragraph(inline_nodes):
        """Push inline_nodes into adf_content as a paragraph and clear them."""
        if inline_nodes:
            adf_content.append({"type": "paragraph", "content": inline_nodes.copy()})
            inline_nodes.clear()

    def make_text_node(text: str) -> dict:
        return {"type": "text", "text": text}

    def make_link_node(text: str, href: str) -> dict:
        return {"type": "text", "text": text, "marks": [{"type": "link", "attrs": {"href": href}}]}

    def handle_image_tag(img_tag):
        """Download/upload image and insert mediaSingle (preferred) or fallback link."""
        src = img_tag.get("src") or ""
        if src and ATTACH_URL_SUBSTR in src:
            local_file = download_images_to_ado_attachments(src)
            if not local_file:
                return
            upload = jira_upload_attachment(issue_key, local_file)
            if upload and upload.get("id"):
                adf_content.append({
                    "type": "mediaSingle",
                    "content": [{
                        "type": "media",
                        "attrs": {
                            "type": "external",
                            "url": f"{JIRA_URL}/rest/api/2/attachment/content/{upload['id']}",
                            "width": 710,
                            "height": 163
                        }
                    }]
                })
            elif upload and upload.get("content"):
                adf_content.append({
                    "type": "paragraph",
                    "content": [{
                        "type": "text",
                        "text": upload.get("filename") or "Attachment",
                        "marks": [{"type": "link", "attrs": {"href": upload["content"]}}]
                    }]
                })
        elif src:
            # non-ADO image: fallback to link
            adf_content.append({
                "type": "paragraph",
                "content": [{
                    "type": "text",
                    "text": src,
                    "marks": [{"type": "link", "attrs": {"href": src}}]
                }]
            })

    def process_nodes(nodes, inline_acc):
        """Process nodes sequentially, preserving order."""
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
                        # duplicate link → keep label as plain text
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

            # inline container (span, strong, em, etc.)
            process_nodes(node.children, inline_acc)

    # parse top-level nodes
    inline_nodes = []
    process_nodes(soup.contents, inline_nodes)
    if inline_nodes:
        flush_paragraph(inline_nodes)

    # fallback: plain text of raw_html if nothing extracted
    if not adf_content:
        import re, html as html_lib
        fallback_text = re.sub(r"<[^>]+>", " ", raw_html)
        fallback_text = html_lib.unescape(fallback_text).strip()
        if fallback_text:
            adf_content = [{"type": "paragraph", "content": [make_text_node(fallback_text)]}]

    return {"type": "doc", "version": 1, "content": adf_content}


def process_description_with_attachments(issue_key: str, raw_html: str) -> Dict:
    """Convert ADO HTML description into Jira ADF with images preserved."""
    if not raw_html:
        return to_adf_doc("")

    soup = BeautifulSoup(raw_html, "html.parser")

    # Collect images
    for img in soup.find_all("img"):
        src = img.get("src")
        if src and ATTACH_URL_SUBSTR in src:
            filename = parse_qs(urlparse(src).query or "").get("fileName", ["embedded.png"])[0]
            local_file = download_images_to_ado_attachments(src)
            content_url = jira_upload_attachment(issue_key, local_file)
            if content_url:
                 img.replace_with(f"!{filename}!")


    # Handle links <a>
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
    seen_steps = set()  # To avoid duplicates
    step_no = 0

    # Base Jira table structure
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
                            # Header row
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

    # Sort steps by ID to ensure order
    steps_sorted = sorted(root.findall(".//step[@type]"), key=lambda x: int(x.get("id", 0)))

    for step in steps_sorted:
        step_type = step.get("type")
        ps_list = step.findall("parameterizedString")
        action_text = ""
        expected_text = ""

        if step_type == "ActionStep":
            # Combine all non-empty parameterizedString texts
            action_text = " ".join(clean_html_steps(p.text) for p in ps_list if p.text)
            expected_text = " "  # ActionStep has no expected results
        elif step_type == "ValidateStep":
            if len(ps_list) >= 2:
                action_text = clean_html_steps(ps_list[0].text)
                expected_text = clean_html_steps(ps_list[1].text)

        # Skip duplicates and empty steps
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

### For repro steps convert_ado_reprosteps_to_jira_adf and download_and_upload_reprosteps_images functions are used
def download_and_upload_reprosteps_images(issue_key: str, repro_html: str) -> Dict[str, str]:
    """
    Extract all <img> URLs from ReproSteps HTML, download them,
    upload to Jira, and return mapping: {ADO URL → Jira attachment ID}
    """
    attachment_map = {}
    if not repro_html:
        return attachment_map

    soup = BeautifulSoup(repro_html, "html.parser")
    imgs = soup.find_all("img")

    for img in imgs:
        src = img.get("src")
        if src and ATTACH_URL_SUBSTR in src and src not in attachment_map:
            # Get filename from URL
            filename = parse_qs(urlparse(src).query or "").get("fileName", ["attachment.png"])[0]
            
            # Download from ADO
            local_file = ado_download_attachment(src, filename)
            if not local_file:
                log(f"   ⚠️ Failed to download: {src}")
                continue
            
            # Upload to Jira
            upload_info = jira_upload_attachment(issue_key, local_file)
            if upload_info and upload_info.get("id"):
                attachment_map[src] = upload_info["id"]
                log(f"   ✅ Mapped: {filename} → Jira ID {upload_info['id']}")
            else:
                log(f"   ⚠️ Failed to upload: {filename}")

    return attachment_map


def convert_ado_reprosteps_to_jira_adf(html_input: str, attachment_map: Dict[str, str] = None, issue_key: str = None) -> Dict:
    """
    Converts ADO ReproSteps HTML → Jira ADF.
    Handles: tables with images, plain tables, text, text with images
    Uses attachment_map to replace <img> with Jira file attachments
    """
    if not html_input:
        return {"type": "doc", "version": 1, "content": []}

    soup = BeautifulSoup(html_input, "html.parser")
    doc_content: List = []
    attachment_map = attachment_map or {}

    def create_media_node(src: str, use_external_fallback: bool = True):
        """Helper to create media node with proper error handling"""
        if src in attachment_map:
            jira_id = attachment_map[src]
            # Use external URL approach for better reliability
            base = clean_base(JIRA_URL)
            attachment_url = f"{base}/rest/api/3/attachment/content/{jira_id}"
            return {
                "type": "mediaSingle",
                "attrs": {"layout": "center"},
                "content": [{
                    "type": "media",
                    "attrs": {
                        "type": "external",
                        "url": attachment_url
                    }
                }]
            }
        elif use_external_fallback:
            # Fallback: external URL (original ADO URL)
            return {
                "type": "mediaSingle",
                "attrs": {"layout": "center"},
                "content": [{
                    "type": "media",
                    "attrs": {
                        "type": "external",
                        "url": src
                    }
                }]
            }
        return None

    def process_text_content(element):
        """Process text content with formatting (bold, etc.)"""
        para_content = []
        
        for child in element.children:
            if hasattr(child, 'name'):
                if child.name in ["b", "strong"]:
                    text = child.get_text(strip=True)
                    if text:
                        para_content.append({
                            "type": "text",
                            "text": text,
                            "marks": [{"type": "strong"}]
                        })
                elif child.name in ["i", "em"]:
                    text = child.get_text(strip=True)
                    if text:
                        para_content.append({
                            "type": "text",
                            "text": text,
                            "marks": [{"type": "em"}]
                        })
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

    # ===========================================
    # 1. PROCESS TABLES (with or without images)
    # ===========================================
    tables = soup.find_all("table")
    for table in tables:
        rows = []
        for tr in table.find_all("tr"):
            cells = []
            for td in tr.find_all(["td", "th"]):
                cell_blocks = []

                # --- Handle images in cells ---
                images_found = False
                for img in td.find_all("img"):
                    src = img.get("src")
                    if src:
                        media_node = create_media_node(src)
                        if media_node:
                            cell_blocks.append(media_node)
                            images_found = True
                    img.decompose()  # Remove img so it doesn't appear in text

                # --- Handle text in cells ---
                cell_text = td.get_text(" ", strip=True)
                if cell_text:
                    para_content = process_text_content(td)
                    
                    if para_content:
                        cell_blocks.append({
                            "type": "paragraph",
                            "content": para_content
                        })

                # If cell is empty, add empty paragraph
                if not cell_blocks:
                    cell_blocks = [{"type": "paragraph", "content": []}]

                # Determine cell type (header vs regular)
                cell_type = "tableHeader" if td.name == "th" else "tableCell"
                cells.append({"type": cell_type, "content": cell_blocks})
            
            if cells:
                rows.append({"type": "tableRow", "content": cells})

        if rows:
            doc_content.append({
                "type": "table",
                "attrs": {
                    "isNumberColumnEnabled": False,
                    "layout": "default"
                },
                "content": rows
            })
        
        # Remove processed table from soup
        table.decompose()

    # Add separator after tables if any were processed
    if tables and doc_content:
        doc_content.append({"type": "rule"})

    # ===========================================
    # 2. PROCESS NON-TABLE CONTENT (text with/without images)
    # ===========================================
    
    # Process remaining content
    remaining_elements = soup.find_all(["div", "p", "img"], recursive=False)
    
    # If no specific elements found, get all remaining text
    if not remaining_elements:
        remaining_text = soup.get_text(" ", strip=True)
        if remaining_text:
            doc_content.append({
                "type": "paragraph",
                "content": [{"type": "text", "text": remaining_text}]
            })
    else:
        for element in remaining_elements:
            # Handle standalone images
            if element.name == "img":
                src = element.get("src")
                if src:
                    media_node = create_media_node(src)
                    if media_node:
                        doc_content.append(media_node)
                element.decompose()
                continue
            
            # --- Handle images within divs/paragraphs ---
            for img in element.find_all("img"):
                src = img.get("src")
                if src:
                    media_node = create_media_node(src)
                    if media_node:
                        doc_content.append(media_node)
                img.decompose()

            # --- Handle text paragraphs ---
            text = element.get_text(" ", strip=True)
            if text:
                para_content = process_text_content(element)
                
                if para_content:
                    doc_content.append({
                        "type": "paragraph",
                        "content": para_content
                    })

    # If no content at all, add empty paragraph
    if not doc_content:
        doc_content = [{"type": "paragraph", "content": []}]
    
    return {"type": "doc", "version": 1, "content": doc_content}

# def build_jira_fields_from_ado(wi: Dict) -> Dict:
#     global steps_payload
#     steps_payload = None

#     f = wi.get("fields", {})
#     # print(f,"testfields")
#     steps=f.get("Microsoft.VSTS.TCM.Steps"," ")
#     print(steps,"steps_field")
#     if steps:
#         steps_payload=steps_formatter(steps)

#     summary = f.get("System.Title", "No Title")
#     raw_desc = f.get("System.Description", "")
#     desc_text = clean_html_to_text(raw_desc)

#     ado_type = f.get("System.WorkItemType", "Task")
#     jira_issuetype = WORKITEM_TYPE_MAP.get(ado_type, "Task")

#     tags = f.get("System.Tags", "")

#     labels: List[str] = []
#     if tags:
#         parts = re.split(r"[;,]", tags)
#         labels = [p.strip().replace(" ", "-") for p in parts if p.strip()]

#     ado_priority_val = f.get("Microsoft.VSTS.Common.Priority")
#     try:
#         ado_priority_int = int(ado_priority_val) if ado_priority_val is not None else None
#     except Exception:
#         ado_priority_int = None
#     jira_priority_name = PRIORITY_MAP.get(ado_priority_int or -1)

#     assignee_email = None
#     assigned_to = f.get("System.AssignedTo")
#     if isinstance(assigned_to, dict):
#         assignee_email = assigned_to.get("uniqueName") or assigned_to.get("mail")

#     # Save original ADO state for post-creation transition
#     ado_state = f.get("System.State", "New")
#     print(f.get("System.CreatedDate"))
#     print(f.get("Microsoft.VSTS.Scheduling.TargetDate"))
#     print(f,"test")
#     fields: Dict = {
#         "project": {"key": JIRA_PROJECT_KEY},
#         "summary": summary,
#         "issuetype": {"name": jira_issuetype},
#         "description" : to_adf_doc(" "), # set placeholder first

#         "labels": labels,
        
#     #    "customfield_10015": convert_ado_datetime(
#     #     f.get("System.CreatedDate", "")
#     #     ),

#         # "duedate": convert_ado_datetime(
#         # f.get("Microsoft.VSTS.Scheduling.TargetDate", "")
#         # )
         
#         }
    
#     # fields["customfield_10015"] = convert_ado_datetime(
#     #     f.get("System.CreatedDate")
#     #     )

#     created_date = f.get("System.CreatedDate")
#     if created_date:
#         fields["customfield_10015"] = convert_ado_datetime(created_date)

#     target_date = f.get("Microsoft.VSTS.Scheduling.TargetDate")
#     if target_date:
#         fields["duedate"] = convert_ado_datetime(target_date)

#     # Priority Rank
#     priority_rank = f.get("Custom.PriorityRank")
#     if priority_rank is not None:
#         try:
#             fields["customfield_11700"] = float(priority_rank) 
#         except ValueError:
#             pass

#     # Go Live Date → Jira custom field
#     go_live_date = f.get("Custom.GoLiveDate")
#     if go_live_date:
#         fields["customfield_12416"] = convert_ado_datetime(go_live_date)

#     tshirt_size = f.get("Custom.TShirtSize")
#     print(tshirt_size)
#     if tshirt_size:
#         fields["customfield_11791"] = {"value": tshirt_size}
#     print(fields,"tshirt_size")

#     latest_release_version = f.get("Custom.LatestReleaseVersion")
#     if latest_release_version:
#         fields["customfield_11793"] = to_adf_doc(str(latest_release_version))

#     latest_release = f.get("Custom.LatestRelease")
#     if latest_release:
#         fields["customfield_11792"] = to_adf_doc(str(latest_release))

#     custom_status = f.get("Custom.Status")
#     if custom_status:
#         fields["customfield_11794"] = {"value": custom_status}
    
#     # Custom field: Value Stream (single-select)
#     value_stream = f.get("Custom.ValueStream")
#     if value_stream:
#         fields["customfield_11702"] = {"value": value_stream}  

#     customer_name = f.get("Custom.CustomerName")
#     if customer_name:
#         # ADO multi-select values are semicolon-separated
#         parts = [c.strip() for c in customer_name.split(";") if c.strip()]
#         fields["customfield_12350"] = [{"value": p} for p in parts]

#     deliverable_type = f.get("Custom.DeliverableType") 
#     if deliverable_type:
#         fields["customfield_11707"] = {"value": deliverable_type} 

#     account_id = get_jira_account_id_for_email(assignee_email)
#     print(f"🔎 ADO assignee email: {assignee_email}")
#     print(f"🔎 Jira accountId mapped: {account_id}")
    
#     if account_id:
#         fields["assignee"] = {"id": account_id}
#     # Reporter mapping
#     created_by = f.get("System.CreatedBy")
#     reporter_email = None
#     if isinstance(created_by, dict):
#         reporter_email = created_by.get("uniqueName", "").lower().strip()

#     if reporter_email in USER_MAP:
#         fields["reporter"] = {"id": USER_MAP[reporter_email]}
#     else:
#         fields["reporter"] = {"id": DEFAULT_REPORTER_ACCOUNT_ID}

#     cap_required = f.get("Custom.CAPRequired")   
#     if cap_required:
#         fields["customfield_11795"] = {"value": cap_required}

#     priority_level = f.get("Custom.PriorityLevel")
#     if priority_level:
#         fields["customfield_12317"] = {"value": priority_level}

#     strategic_theme = f.get("Custom.StrategicTheme")
#     if strategic_theme:
#         fields["customfield_11796"] = {"value": strategic_theme}

#     module_type = f.get("Custom.ModuleType")   # use exact ADO reference name
#     if module_type:
#         fields["customfield_11797"] = {"value": module_type}

#     horizon = f.get("Custom.Horizon")  
#     if horizon:
#         fields["customfield_11798"] = {"value": horizon}

#     value_drivers = f.get("Custom.ValueDrivers")   
#     if value_drivers:
#         fields["customfield_11799"] = {"value": value_drivers}

#     business_objective = f.get("Custom.BusinessObjectiveOKR")   # exact ADO reference name
#     if business_objective:
#         fields["customfield_11801"] = {"value": business_objective}

#     team_dependency = f.get("Custom.TeamDependency")
#     if team_dependency:
#         # ADO returns multi-select as semicolon-separated string
#         parts = [p.strip() for p in team_dependency.split(";") if p.strip()]
#         fields["customfield_11324"] = [{"value": p} for p in parts]

#     pi_values = f.get("Custom.PI")
#     if pi_values:
#         # ADO returns multi-select as semicolon-separated string
#         parts = [p.strip() for p in pi_values.split(";") if p.strip()]
#         fields["customfield_11802"] = [{"value": p} for p in parts]

#     if jira_priority_name:
#         fields["priority"] = {"name": jira_priority_name}

#     # wid = f.get("System.Id")
#     # print(wid)
#     # if wid:
#     #     fields["customfield_11600"] = str(wid)

#     # Replaces the ADO ID in the place of ID with the ADO workitem Link
#     wid = f.get("System.Id")
#     print(wid)
#     if wid:
#         # Store the ID in your custom field
#         fields["customfield_11600"] = str(wid)

#         # Build the ADO work item URL (UI link)
#         ado_base = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}"
#         ado_ui_link = f"{ado_base}/_workitems/edit/{wid}"

#         # Optionally, store this link in another custom field in Jira
#         fields["customfield_11600"] = ado_ui_link  # replace XXXXX with your custom field ID
#         print("ADO WorkItem Link:", ado_ui_link)

#     area = f.get("System.AreaPath")
#     print(area)
#     if area:
#         fields["customfield_11601"] = str(area)

#     iteration = f.get("System.IterationPath")
#     print(iteration)
#     if iteration:
#         fields["customfield_11602"] = str(iteration)

#     reason = f.get("System.Reason")
#     print(reason)
#     if reason:
#         fields["customfield_11603"] = str(reason)
    
#     return fields

def build_jira_fields_from_ado(wi: Dict) -> Dict:
    global steps_payload
    steps_payload = None

    f = wi.get("fields", {})
    wi_id = wi.get("id")
    
    # Log start
    log_to_excel(wi_id, None, "Build Fields", "Started", "Building Jira fields from ADO")
    
    # Steps field
    steps = f.get("Microsoft.VSTS.TCM.Steps", " ")
    print(steps, "steps_field")
    if steps and steps.strip() != " ":
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
    log_to_excel(wi_id, None, "Issue Type", "Success", f"ADO: {ado_type} → Jira: {jira_issuetype}")

    tags = f.get("System.Tags", "")

    labels: List[str] = []
    if tags:
        parts = re.split(r"[;,]", tags)
        labels = [p.strip().replace(" ", "-") for p in parts if p.strip()]
        log_to_excel(wi_id, None, "Labels", "Success", f"Mapped {len(labels)} labels")
    else:
        log_to_excel(wi_id, None, "Labels", "Skipped", "No tags in ADO")
    
    # Priority 
    ado_priority_val = f.get("Microsoft.VSTS.Common.Priority")
    try:
        ado_priority_int = int(ado_priority_val) if ado_priority_val is not None else None
    except Exception:
        ado_priority_int = None
    jira_priority_name = PRIORITY_MAP.get(ado_priority_int or -1)
    
    if jira_priority_name:
        log_to_excel(wi_id, None, "Priority", "Success", f"ADO: {ado_priority_int} → Jira: {jira_priority_name}")
    else:
        log_to_excel(wi_id, None, "Priority", "Skipped", "No priority mapping")

    assignee_email = None
    assigned_to = f.get("System.AssignedTo")
    if isinstance(assigned_to, dict):
        assignee_email = assigned_to.get("uniqueName") or assigned_to.get("mail")

    # Save original ADO state for post-creation transition
    ado_state = f.get("System.State", "New")
    print(f.get("System.CreatedDate"))
    print(f.get("Microsoft.VSTS.Scheduling.TargetDate"))
    print(f, "test")
    
    fields: Dict = {
        "project": {"key": JIRA_PROJECT_KEY},
        "summary": summary,
        "issuetype": {"name": jira_issuetype},
        "description": to_adf_doc(" "),  # set placeholder first
        "labels": labels,
    }

    # Created Date
    created_date = f.get("System.CreatedDate")
    if created_date:
        try:
            fields["customfield_12527"] = convert_ado_datetime(created_date)
            log_to_excel(wi_id, None, "Created Date", "Success", f"Mapped: {created_date}")
        except Exception as e:
            log_to_excel(wi_id, None, "Created Date", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Created Date", "Skipped", "No created date in ADO")

    # Target/Due Date
    target_date = f.get("Microsoft.VSTS.Scheduling.TargetDate")
    if target_date:
        try:
            fields["duedate"] = convert_ado_datetime(target_date)
            log_to_excel(wi_id, None, "Due Date", "Success", f"Mapped: {target_date}")
        except Exception as e:
            log_to_excel(wi_id, None, "Due Date", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Due Date", "Skipped", "No target date in ADO")

    # Priority Rank
    priority_rank = f.get("Custom.PriorityRank")
    if priority_rank is not None:
        try:
            fields["customfield_11700"] = float(priority_rank)
            log_to_excel(wi_id, None, "Priority Rank", "Success", f"Value: {priority_rank}")
        except ValueError as e:
            log_to_excel(wi_id, None, "Priority Rank", "Error", f"Invalid value: {priority_rank}")
    else:
        log_to_excel(wi_id, None, "Priority Rank", "Skipped", "No priority rank in ADO")

    # Go Live Date
    go_live_date = f.get("Custom.GoLiveDate")
    if go_live_date:
        try:
            fields["customfield_12416"] = convert_ado_datetime(go_live_date)
            log_to_excel(wi_id, None, "Go Live Date", "Success", f"Mapped: {go_live_date}")
        except Exception as e:
            log_to_excel(wi_id, None, "Go Live Date", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Go Live Date", "Skipped", "No go live date in ADO")

    start_date = f.get("Microsoft.VSTS.Scheduling.StartDate")
    if start_date:
        try:
            fields["customfield_10015"] = convert_ado_datetime(start_date)
            log_to_excel(wi_id, None, "Start Date", "Success", f"Mapped: {start_date}")
        except Exception as e:
            log_to_excel(wi_id, None, "Start Date", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Start Date", "Skipped", "No start date in ADO")

    # T-Shirt Size
    tshirt_size = f.get("Custom.TShirtSize")
    print(tshirt_size)
    if tshirt_size:
        try:
            fields["customfield_11791"] = {"value": tshirt_size}
            log_to_excel(wi_id, None, "T-Shirt Size", "Success", f"Value: {tshirt_size}")
        except Exception as e:
            log_to_excel(wi_id, None, "T-Shirt Size", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "T-Shirt Size", "Skipped", "No t-shirt size in ADO")
    print(fields, "tshirt_size")

    # Latest Release Version
    latest_release_version = f.get("Custom.LatestReleaseVersion")
    if latest_release_version:
        try:
            fields["customfield_11793"] = to_adf_doc(str(latest_release_version))
            log_to_excel(wi_id, None, "Release Version", "Success", f"Value: {latest_release_version}")
        except Exception as e:
            log_to_excel(wi_id, None, "Release Version", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Release Version", "Skipped", "No release version in ADO")

    # Latest Release
    latest_release = f.get("Custom.LatestRelease")
    if latest_release:
        try:
            fields["customfield_11792"] = to_adf_doc(str(latest_release))
            log_to_excel(wi_id, None, "Latest Release", "Success", f"Value: {latest_release}")
        except Exception as e:
            log_to_excel(wi_id, None, "Latest Release", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Latest Release", "Skipped", "No latest release in ADO")

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

    # Value Stream
    value_stream = f.get("Custom.ValueStream")
    if value_stream:
        try:
            fields["customfield_11702"] = {"value": value_stream}
            log_to_excel(wi_id, None, "Value Stream", "Success", f"Value: {value_stream}")
        except Exception as e:
            log_to_excel(wi_id, None, "Value Stream", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Value Stream", "Skipped", "No value stream in ADO")

    # Customer Name (multi-select)
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

    # Deliverable Type
    deliverable_type = f.get("Custom.DeliverableType")
    if deliverable_type:
        try:
            fields["customfield_11707"] = {"value": deliverable_type}
            log_to_excel(wi_id, None, "Deliverable Type", "Success", f"Value: {deliverable_type}")
        except Exception as e:
            log_to_excel(wi_id, None, "Deliverable Type", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Deliverable Type", "Skipped", "No deliverable type in ADO")

    # Assignee
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
            log_to_excel(wi_id, None, "Assignee", "Warning", f"No mapping for: {assignee_email}")
        else:
            log_to_excel(wi_id, None, "Assignee", "Skipped", "No assignee in ADO")
    
    # Reporter
    created_by = f.get("System.CreatedBy")
    reporter_email = None
    if isinstance(created_by, dict):
        reporter_email = created_by.get("uniqueName", "").lower().strip()

    if reporter_email in USER_MAP:
        try:
            fields["reporter"] = {"id": USER_MAP[reporter_email]}
            log_to_excel(wi_id, None, "Reporter", "Success", f"Email: {reporter_email} → ID: {USER_MAP[reporter_email]}")
        except Exception as e:
            log_to_excel(wi_id, None, "Reporter", "Error", str(e)[:100])
    else:
        try:
            fields["reporter"] = {"id": DEFAULT_REPORTER_ACCOUNT_ID}
            if reporter_email:
                log_to_excel(wi_id, None, "Reporter", "Info", f"No mapping for {reporter_email}, using default")
            else:
                log_to_excel(wi_id, None, "Reporter", "Info", "Using default reporter")
        except Exception as e:
            log_to_excel(wi_id, None, "Reporter", "Error", str(e)[:100])

    # CAP Required
    cap_required = f.get("Custom.CAPRequired")
    if cap_required:
        try:
            fields["customfield_11795"] = {"value": cap_required}
            log_to_excel(wi_id, None, "CAP Required", "Success", f"Value: {cap_required}")
        except Exception as e:
            log_to_excel(wi_id, None, "CAP Required", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "CAP Required", "Skipped", "No CAP required in ADO")

    # Priority Level
    priority_level = f.get("Custom.PriorityLevel")
    if priority_level:
        try:
            fields["customfield_12317"] = {"value": priority_level}
            log_to_excel(wi_id, None, "Priority Level", "Success", f"Value: {priority_level}")
        except Exception as e:
            log_to_excel(wi_id, None, "Priority Level", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Priority Level", "Skipped", "No priority level in ADO")

    # Strategic Theme
    strategic_theme = f.get("Custom.StrategicTheme")
    if strategic_theme:
        try:
            fields["customfield_11796"] = {"value": strategic_theme}
            log_to_excel(wi_id, None, "Strategic Theme", "Success", f"Value: {strategic_theme}")
        except Exception as e:
            log_to_excel(wi_id, None, "Strategic Theme", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Strategic Theme", "Skipped", "No strategic theme in ADO")

    # Module Type
    module_type = f.get("Custom.ModuleType")
    if module_type:
        try:
            fields["customfield_11797"] = {"value": module_type}
            log_to_excel(wi_id, None, "Module Type", "Success", f"Value: {module_type}")
        except Exception as e:
            log_to_excel(wi_id, None, "Module Type", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Module Type", "Skipped", "No module type in ADO")

    # Horizon
    horizon = f.get("Custom.Horizon")
    if horizon:
        try:
            fields["customfield_11798"] = {"value": horizon}
            log_to_excel(wi_id, None, "Horizon", "Success", f"Value: {horizon}")
        except Exception as e:
            log_to_excel(wi_id, None, "Horizon", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Horizon", "Skipped", "No horizon in ADO")

    # Value Drivers
    value_drivers = f.get("Custom.ValueDrivers")
    if value_drivers:
        try:
            fields["customfield_11799"] = {"value": value_drivers}
            log_to_excel(wi_id, None, "Value Drivers", "Success", f"Value: {value_drivers}")
        except Exception as e:
            log_to_excel(wi_id, None, "Value Drivers", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Value Drivers", "Skipped", "No value drivers in ADO")

    # Business Objective
    business_objective = f.get("Custom.BusinessObjectiveOKR")
    if business_objective:
        try:
            fields["customfield_11801"] = {"value": business_objective}
            log_to_excel(wi_id, None, "Business Objective", "Success", f"Value: {business_objective}")
        except Exception as e:
            log_to_excel(wi_id, None, "Business Objective", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Business Objective", "Skipped", "No business objective in ADO")

    # Team Dependency (multi-select)
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

    # PI (multi-select)
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

    # Priority (if mapped)
    if jira_priority_name:
        try:
            fields["priority"] = {"name": jira_priority_name}
        except Exception as e:
            log_to_excel(wi_id, None, "Set Priority Field", "Error", str(e)[:100])

    # ADO Work Item Link
    wid = f.get("System.Id")
    print(wid)
    if wid:
        try:
            # Store the ID in your custom field
            fields["customfield_11600"] = str(wid)

            # Build the ADO work item URL (UI link)
            ado_base = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}"
            ado_ui_link = f"{ado_base}/_workitems/edit/{wid}"

            # Optionally, store this link in another custom field in Jira
            fields["customfield_11600"] = ado_ui_link
            print("ADO WorkItem Link:", ado_ui_link)
            log_to_excel(wi_id, None, "ADO Work Item Link", "Success", f"Link: {ado_ui_link}")
        except Exception as e:
            log_to_excel(wi_id, None, "ADO Work Item Link", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "ADO Work Item Link", "Warning", "No System.Id found")

    # Area Path
    area = f.get("System.AreaPath")
    print(area)
    if area:
        try:
            fields["customfield_11601"] = str(area)
            log_to_excel(wi_id, None, "Area Path", "Success", f"Value: {area}")
        except Exception as e:
            log_to_excel(wi_id, None, "Area Path", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Area Path", "Skipped", "No area path in ADO")

    # Iteration Path
    iteration = f.get("System.IterationPath")
    print(iteration)
    if iteration:
        try:
            fields["customfield_11602"] = str(iteration)
            log_to_excel(wi_id, None, "Iteration Path", "Success", f"Value: {iteration}")
        except Exception as e:
            log_to_excel(wi_id, None, "Iteration Path", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Iteration Path", "Skipped", "No iteration path in ADO")

    # Reason
    reason = f.get("System.Reason")
    print(reason)
    if reason:
        try:
            fields["customfield_11603"] = str(reason)
            log_to_excel(wi_id, None, "Reason", "Success", f"Value: {reason}")
        except Exception as e:
            log_to_excel(wi_id, None, "Reason", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Reason", "Skipped", "No reason in ADO")

    # Log completion
    log_to_excel(wi_id, None, "Build Fields", "Completed", f"Built {len(fields)} fields successfully")
    
    return fields

OUTPUT_DIR = "ado_attachments"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def jira_transition_issue(issue_key: str, ado_state: str):
    target_status = STATE_MAP.get(ado_state)
    if not target_status:
        return

    base = clean_base(JIRA_URL)
    # Get available transitions
    url = f"{base}/rest/api/3/issue/{issue_key}/transitions"
    r = requests.get(url, auth=jira_auth(), headers={"Accept": "application/json"})
    if r.status_code != 200:
        log(f"⚠️ Failed to fetch transitions for {issue_key}")
        return

    transitions = r.json().get("transitions", [])
    transition_id = None
    for t in transitions:
        if t["to"]["name"] == target_status:
            transition_id = t["id"]
            break

    if not transition_id:
        log(f"⚠️ No transition found from current status to '{target_status}' for {issue_key}")
        return

    # Perform the transition
    url = f"{base}/rest/api/3/issue/{issue_key}/transitions"
    payload = {"transition": {"id": transition_id}}
    r = requests.post(url, auth=jira_auth(), headers={"Content-Type": "application/json"}, json=payload)
    if r.status_code in (200, 204):
        log(f"✅ {issue_key} transitioned to '{target_status}'")
    else:
        log(f"⚠️ Failed to transition {issue_key} -> {target_status}: {r.status_code} {r.text}")

def download_images_to_ado_attachments(url):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    # Get filename from query string or fallback
    if "fileName" in query:
        filename = query["fileName"][0]
    else:
        filename = os.path.basename(parsed.path)

    output_file = os.path.join(OUTPUT_DIR, filename)

    # Always call the API (outside if/else)
    response = requests.get(url, auth=HTTPBasicAuth("", ADO_PAT), stream=True)

    if response.status_code == 200:
        with open(output_file, "wb") as f:
            for chunk in response.iter_content(1024):
                f.write(chunk)
        print(f"✅ Image downloaded as {output_file}")
        return output_file
    else:
        print(f"❌ Failed: {response.status_code} - {response.text}")

def jira_add_comment_for_link(issue_key: str, body: str):
    url = f"{JIRA_URL}/rest/api/2/issue/{issue_key}/comment"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    auth = HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN)

    payload = {
        "body": body
    }

    response = requests.post(url, headers=headers, auth=auth, json=payload)
    if response.status_code == 201:
        print(f"✅ Comment added to {issue_key}")
    else:
        print(f"❌ Failed to add comment: {response.status_code}, {response.text}")

def clean_html_to_jira_format(issue_key: str,html_text: str) -> str:
    if not html_text:
        return ""
    image_urls = re.findall(r'<img[^>]+src="([^"]+)"', html_text)

    # Decode HTML entities
    html_text = html.unescape(html_text)

    # Handle <br> tags → convert to newline
    html_text = re.sub(r"(?i)<br\s*/?>", "\n", html_text)


    # If <a> tags exist → convert to Jira wiki link format
    if "<a" in html_text.lower():
        soup = BeautifulSoup(html_text, "html.parser")

        for a in soup.find_all("a"):
            href = a.get("href", "").strip()
            text = a.get_text(strip=True) or href  # ✅ Prefer text, fallback to href
            if href:
                jira_link = f"[{text}|{href}]"
                a.replace_with(jira_link)

        # Remove any remaining HTML tags
        clean_text = re.sub(r"<[^>]+>", " ", str(soup)).strip()
        if image_urls:
            print("Link with Image")
            for i in image_urls:
                local_file = download_images_to_ado_attachments(i)
                content_url=jira_upload_attachment(issue_key, local_file)  
                jira_upload_attachment_as_comment(issue_key, content_url,clean_text)
        else:
            print("only Link")
            jira_add_comment_for_link(issue_key,clean_text)
        return " "

    else:
        # No <a> tag → return plain text
        return re.sub(r"<[^>]+>", " ", html_text).strip()

def ado_api_to_ui_link(api_url):
    """
    Convert ADO work item API URL to the web UI link
    """
    match = re.search(r'/workItems/(\d+)', api_url)
    if not match:
        return api_url  # fallback to original if not a work item URL
    workitem_id = match.group(1)
    ui_url = re.sub(r'_apis/wit/workItems/\d+', f'_workitems/edit/{workitem_id}', api_url)
    return ui_url

def extract_wid(url):
    """
    Extract ADO work item ID from API URL
    """
    match = re.search(r'/workItems/(\d+)', url)
    return match.group(1) if match else None

def fetch_ado_workitem_title(wid):
    url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/workitems/{wid}?api-version=7.1"
    r = requests.get(url, auth=ado_auth())
    r.raise_for_status()
    data = r.json()
    title = data["fields"].get("System.Title", "ADO Work Item")
    wi_type = data["fields"].get("System.WorkItemType", "")
    return title, wi_type

def create_links_from_ado(wi, issue_key):
    """
    Create Jira remote links for ADO relations.
    - Converts API links to UI links
    - Fetches ADO ID + Title
    - Adds relationship type (Parent / Child / Affects)
    - Safe with try/except
    """
    relations = wi.get("relations", [])
    if not relations:
        print(f"No relations found for ADO work item → Jira {issue_key}")
        return

    base = clean_base(JIRA_URL)

    for rel in relations:
        try:
            url = rel.get("url")
            rel_type = rel.get("attributes", {}).get("name", "Related")

            # Skip invalid / GitHub artifact links
            if not url or url.startswith("vstfs:///"):
                print(f"Skipping artifact link for {issue_key}")
                continue

            # Only handle ADO work item links
            if "_apis/wit/workItems" not in url:
                print(f"Skipping non-workitem link: {url}")
                continue

            # Extract ADO Work Item ID
            wid = extract_wid(url)
            if not wid:
                print(f"Could not extract work item ID from {url}")
                continue

            # Fetch title from ADO
            title, _ = fetch_ado_workitem_title(wid)

            # Convert API → UI link
            ado_ui_url = ado_api_to_ui_link(url)

            payload = {
                "object": {
                    "url": ado_ui_url,
                    "title": f"[{rel_type}] {wid} | {title}"
                }
            }

            link_url = f"{base}/rest/api/3/issue/{issue_key}/remotelink"

            r = requests.post(
                link_url,
                json=payload,
                auth=jira_auth(),
                headers={"Content-Type": "application/json"}
            )

            if r.status_code in (200, 201):
                print(f"✔ Linked [{rel_type}] {wid} | {title} → Jira {issue_key}")
            else:
                print(
                    f"✖ Failed linking {wid} → Jira {issue_key} | "
                    f"Status: {r.status_code} | Response: {r.text}"
                )

        except Exception as e:
            print(
                f"❌ Error while processing relation for Jira {issue_key} | "
                f"URL: {url} | Error: {e}"
            )


# Global migration log
# -----------------------------
migration_log = []
# Helper to append messages
# -----------------------------
def log_to_excel(wi_id, issue_key, step, status, message):
    """Append message to migration log."""
    migration_log.append({
        "WorkItemID": wi_id,
        "IssueKey": issue_key or "",
        "Step": step,
        "Status": status,
        "Message": message
    })
    print(f"{wi_id} | {issue_key or 'NA'} | {step} | {status} | {message}")


def migrate_all():
    ensure_dir(ATTACH_DIR)

    # Load existing mapping for idempotency
    if os.path.exists(MAPPING_FILE):
        with open(MAPPING_FILE, "r") as f:
            mapping = json.load(f)
    else:
        mapping = {}

    # Ascending ID order
    wiql = (
"SELECT [System.Id] FROM WorkItems WHERE [System.CreatedDate] >= '2025-12-01' AND [System.CreatedDate] <= '2025-12-10'AND [System.WorkItemType] = 'Epic'"    )
    ids = ado_wiql_all_ids(wiql)
    if not ids:
        log("No work items found.")
        return

    log(f"📌 Found {len(ids)} work items.")

    # -------------------------------
    # 🔹 ADD BATCH CONTROL HERE
    # -------------------------------
    SPECIFIC_ID = None  # 👉 Set your Work Item ID here (e.g. 12345) or keep None for batch mode

    if SPECIFIC_ID:
        # 🟢 Single work item mode
        ids = [SPECIFIC_ID]
        log(f"🎯 Running migration for a single work item: {SPECIFIC_ID}")
    else:
        # 🟡 Normal batch mode
        START_INDEX = 0       # change for next run (0, 10000, 20000…)
        MAX_TO_PROCESS = 10   # how many to migrate this run

        ids = ids[START_INDEX:START_INDEX + MAX_TO_PROCESS]
        log(f"📌 Processing {len(ids)} work items (from index {START_INDEX}) in this run.")
        # -------------------------------

    for batch in chunked(ids, WIQL_PAGE_SIZE):
        time.sleep(SLEEP_BETWEEN_CALLS)
        workitems = ado_get_workitems_by_ids(batch)
        workitems.sort(key=lambda w: w.get("id", 0))
        log(f"➡️  Processing batch of {len(workitems)}")

        for wi in workitems:
            print(wi,"This is the work Item")
            wi_id = int(wi.get("id"))
            wi_id_str = str(wi_id)
            log(f"--- ADO #{wi_id_str} ---")

            if wi_id_str in mapping:
                log_to_excel(wi_id, mapping[wi_id_str], "Migration", "Skipped", "Already migrated")
                continue

            # 1) Create Jira issue
            try:
                fields = build_jira_fields_from_ado(wi)
                issue_key = jira_create_issue(fields)
                if issue_key:
                    log_to_excel(wi_id, issue_key, "Create Issue", "Success", f"Issue {issue_key} created successfully")
                else:
                    log_to_excel(wi_id, None, "Create Issue", "Failed", "Issue creation returned None")
                    continue
            except Exception as e:
                log_to_excel(wi_id, None, "Create Issue", "Error", str(e)[:100])
                continue

            # 🔥 CREATE LINKS
            try:
                create_links_from_ado(wi, issue_key)
                log_to_excel(wi_id, issue_key, "Create Links", "Success", "Links created from ADO relations")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Create Links", "Error", str(e)[:100])

            # # 2️⃣ UPDATE REPRO STEPS
            # repro_steps_html = wi.get("fields", {}).get("Microsoft.VSTS.TCM.ReproSteps", "")
            # if repro_steps_html:
            #     try:
            #         log(f"📎 Processing ReproSteps for {issue_key}")
            #         log_to_excel(wi_id, issue_key, "ReproSteps", "Processing", "Starting ReproSteps processing")
                    
            #         # Download ADO images and upload to Jira
            #         attachment_map = download_and_upload_reprosteps_images(issue_key, repro_steps_html)
                    
            #         if attachment_map:
            #             log(f"📸 Uploaded {len(attachment_map)} images")
            #             log_to_excel(wi_id, issue_key, "ReproSteps Images", "Success", f"Uploaded {len(attachment_map)} images")
            #             time.sleep(2)
            #         else:
            #             log_to_excel(wi_id, issue_key, "ReproSteps Images", "Info", "No images to upload")
                    
            #         # Verify attachments exist
            #         verified_map = {}
            #         for src, att_id in attachment_map.items():
            #             base = clean_base(JIRA_URL)
            #             verify_url = f"{base}/rest/api/3/attachment/{att_id}"
            #             verify_response = requests.get(verify_url, auth=jira_auth())
            #             if verify_response.status_code == 200:
            #                 verified_map[src] = att_id
            #                 log(f"   ✅ Verified attachment: {att_id}")
            #             else:
            #                 log(f"   ⚠️ Attachment {att_id} not found, will use external URL")
            #                 log_to_excel(wi_id, issue_key, "ReproSteps Verify", "Warning", f"Attachment {att_id} not verified")
                    
            #         # Convert HTML to ADF with Jira attachment IDs
            #         jira_repro_adf = convert_ado_reprosteps_to_jira_adf(
            #             repro_steps_html, 
            #             verified_map,
            #             issue_key
            #         )
                    
            #         # Validate ADF has content
            #         if not jira_repro_adf.get("content"):
            #             log(f"   ⚠️ ReproSteps conversion resulted in empty content")
            #             log_to_excel(wi_id, issue_key, "Update ReproSteps", "Warning", "Empty ADF content")
            #         else:
            #             # Log the ADF structure for debugging
            #             content_types = [c.get("type") for c in jira_repro_adf.get("content", [])]
            #             log(f"📝 ADF contains: {', '.join(content_types)}")
                        
            #             adf_preview = json.dumps(jira_repro_adf, indent=2)[:1000]
            #             log(f"🔍 ADF Preview: {adf_preview}")
                        
            #             # Update the custom field
            #             base = clean_base(JIRA_URL)
            #             url = f"{base}/rest/api/3/issue/{issue_key}"
            #             payload = {"fields": {"customfield_10903": jira_repro_adf}}
            #             headers = {"Content-Type": "application/json"}
                        
            #             r = requests.put(url, auth=jira_auth(), headers=headers, json=payload)
                        
            #             if r.status_code in (200, 204):
            #                 log(f"   ✅ Updated ReproSteps for {issue_key}")
            #                 log_to_excel(wi_id, issue_key, "Update ReproSteps", "Success", 
            #                         f"Updated with {len(verified_map)} images")
            #             else:
            #                 error_msg = r.text
            #                 log(f"   ⚠️ Failed to update ReproSteps: {r.status_code}")
            #                 log(f"   Error: {error_msg}")
                            
            #                 # Try to extract specific error from Jira response
            #                 try:
            #                     error_json = r.json()
            #                     if "errors" in error_json:
            #                         log(f"   Jira errors: {error_json['errors']}")
            #                         log_to_excel(wi_id, issue_key, "Update ReproSteps", "Failed", 
            #                                 f"Jira errors: {str(error_json['errors'])[:100]}")
            #                     if "errorMessages" in error_json:
            #                         log(f"   Error messages: {error_json['errorMessages']}")
            #                 except:
            #                     pass
                            
            #                 log_to_excel(wi_id, issue_key, "Update ReproSteps", "Failed", 
            #                         f"HTTP {r.status_code}: {error_msg[:100]}")
                
            #     except Exception as e:
            #         log(f"   ❌ Exception processing ReproSteps: {str(e)}")
            #         import traceback
            #         log(f"   Traceback: {traceback.format_exc()}")
            #         log_to_excel(wi_id, issue_key, "Update ReproSteps", "Error", str(e)[:100])
            # else:
            #     log(f"   ℹ️ No ReproSteps content for {issue_key}")
            #     log_to_excel(wi_id, issue_key, "ReproSteps", "Skipped", "No ReproSteps content in ADO")

            # 2) UPDATE STEPS FIELD
            try:
                url = f"{JIRA_URL}rest/api/3/issue/{issue_key}"
                headers = {"Content-Type": "application/json"}
                
                # ✅ ADD: Check if steps_payload has content
                if steps_payload and steps_payload.strip() != " ":
                    with open("output.txt", "a", encoding="utf-8") as f:
                        f.write(f"{steps_payload}\n")
                    with open("output1.txt", "a", encoding="utf-8") as f:
                        f.write(f"{url}\n{json.dumps(steps_payload, indent=2)}\n\n")
                    
                    r = requests.put(url, auth=jira_auth(), headers=headers, data=steps_payload)
                    print(r.status_code, "test123")
                    
                    if r.status_code in (200, 204):
                        log(f"✅ Updated Steps for {issue_key} with inline images")
                        log_to_excel(wi_id, issue_key, "Update Steps", "Success", "Steps updated successfully")
                    else:
                        log(f"⚠️ Failed to update steps for {issue_key}: {r.status_code} {r.text}")
                        log_to_excel(wi_id, issue_key, "Update Steps", "Failed", f"{r.status_code} {r.text[:100]}")
                else:
                    log_to_excel(wi_id, issue_key, "Update Steps", "Skipped", "No steps content in ADO")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Update Steps", "Error", str(e)[:100])

            # 3) UPDATE DESCRIPTION FIELD
            try:
                print("one")
                raw_desc = wi.get("fields", {}).get("System.Description", "")
                print(raw_desc, "test")
                
                if raw_desc:
                    print("two")
                    log_to_excel(wi_id, issue_key, "Description", "Processing", "Processing description with images")
                    
                    desc_adf = process_description_to_adf(issue_key, raw_desc)
                    base = clean_base(JIRA_URL)
                    url = f"{base}/rest/api/3/issue/{issue_key}"
                    payload = {"fields": {"description": desc_adf}}
                    headers = {"Content-Type": "application/json"}
                    r = requests.put(url, auth=jira_auth(), headers=headers, json=payload)
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

            # Transition to mapped status
            try:
                ado_state = wi.get("fields", {}).get("System.State", "New")
                jira_transition_issue(issue_key, ado_state)
                log_to_excel(wi_id, issue_key, "Transition", "Success", f"Transitioned to {STATE_MAP.get(ado_state, 'NA')}")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Transition", "Error", str(e)[:100])

            # 4) ATTACHMENTS MIGRATION
            try:
                relations = wi.get("relations", [])

                # Filter to only AttachedFile relations
                attachments_to_upload = []
                for rel in relations:
                    if rel.get("rel") == "AttachedFile":
                        att_url = rel.get("url")
                        att_name = rel.get("attributes", {}).get("name", "attachment")
                        if att_url:
                            attachments_to_upload.append((att_url, att_name))

                # Only process if attachments exist
                if attachments_to_upload:
                    log(f"   📎 Processing {len(attachments_to_upload)} attachment(s) for {issue_key}")
                    log_to_excel(wi_id, issue_key, "Attachments", "Processing", f"Found {len(attachments_to_upload)} attachments")
                    
                    # Download and upload each attachment
                    for att_url, att_filename in attachments_to_upload:
                        try:
                            log(f"   Downloading: {att_filename}")
                            
                            # Download from ADO
                            local_path = ado_download_attachment(att_url, att_filename)
                            
                            if local_path and os.path.exists(local_path):
                                # Upload to Jira
                                upload_result = jira_upload_attachment(issue_key, local_path)
                                
                                if upload_result and upload_result.get("id"):
                                    log(f"   ✅ Uploaded attachment: {att_filename}")
                                    log_to_excel(wi_id, issue_key, "Upload Attachment", "Success", 
                                            f"Uploaded {att_filename}")
                                else:
                                    log(f"   ⚠️ Failed to upload: {att_filename}")
                                    log_to_excel(wi_id, issue_key, "Upload Attachment", "Failed", 
                                            f"Upload failed for {att_filename}")
                                
                                # Clean up local file
                                try:
                                    os.remove(local_path)
                                except Exception as e:
                                    log(f"   ⚠️ Could not delete local file {local_path}: {e}")
                            else:
                                log(f"   ⚠️ Download failed for: {att_filename}")
                                log_to_excel(wi_id, issue_key, "Download Attachment", "Failed", 
                                        f"Download failed for {att_filename}")
                                
                        except Exception as e:
                            log(f"   ❌ Error processing attachment {att_filename}: {e}")
                            log_to_excel(wi_id, issue_key, "Process Attachment", "Error", str(e)[:100])
                    
                    log(f"   ✅ Attachment processing complete for {issue_key}")
                else:
                    log(f"   ℹ️ No attachments found for {issue_key}")
                    log_to_excel(wi_id, issue_key, "Attachments", "Skipped", "No attachments in ADO")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Attachments", "Error", str(e)[:100])

            # 5) COMMENTS
            try:
                downloaded_files = []
                comments = ado_get_comments(wi_id)
                
                if comments:
                    log_to_excel(wi_id, issue_key, "Comments", "Processing", f"Found {len(comments)} comments")
                    
                    for c in reversed(comments):
                        html_text = c.get("text") or c.get("renderedText") or ""

                        comment_text = c.get("text") or c.get("renderedText") or ""
                        created_date = c.get("createdDate")
                        author = (c.get("createdBy") or {}).get("displayName", "Unknown User")

                        # Format the timestamp nicely
                        try:
                            dt = datetime.strptime(created_date, "%Y-%m-%dT%H:%M:%S.%fZ")
                            created_str = dt.strftime("%d %b %Y at %H:%M")
                        except Exception:
                            created_str = created_date

                        plain_text = clean_html_to_jira_format(issue_key, html_text)
                        image_urls = re.findall(r'<img[^>]+src="([^"]+)"', html_text)

                        print(html_text, "htmltext", plain_text, "plain_text", image_urls, "imageurl")
                        
                        if plain_text != " ":
                            if plain_text and not image_urls:
                                print("case-1")
                                body = plain_text
                                jira_add_comment(issue_key, body)
                                log_to_excel(wi_id, issue_key, "Add Comment", "Success", f"Comment added: {plain_text[:50]}...")

                            # case 2: image only
                            elif not plain_text and image_urls:
                                print("case 2")
                                try:
                                    for i in image_urls:
                                        local_file = download_images_to_ado_attachments(i)
                                        content_url = jira_upload_attachment(issue_key, local_file)
                                        jira_upload_attachment_as_comment(issue_key, content_url, plain_text)
                                    log_to_excel(wi_id, issue_key, "Add Comment", "Success", f"{len(image_urls)} image-only comment")
                                except Exception as e:
                                    log_to_excel(wi_id, issue_key, "Add Comment", "Error", f"Image comment failed: {str(e)[:100]}")
                            
                            # case 3: text + image
                            else:
                                print("case 3")
                                try:
                                    for i in image_urls:
                                        local_file = download_images_to_ado_attachments(i)
                                        content_url = jira_upload_attachment(issue_key, local_file)
                                        jira_upload_attachment_as_comment(issue_key, content_url, plain_text)
                                    log_to_excel(wi_id, issue_key, "Add Comment", "Success", f"Comment with text + {len(image_urls)} images")
                                except Exception as e:
                                    log_to_excel(wi_id, issue_key, "Add Comment", "Error", f"Text+image comment failed: {str(e)[:100]}")
                        else:
                            continue
                else:
                    log_to_excel(wi_id, issue_key, "Comments", "Skipped", "No comments in ADO")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Comments", "Error", str(e)[:100])
    
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

    if migration_log:
        df = pd.DataFrame(migration_log)
        df.to_excel("migration_log.xlsx", index=False)
        print("✅ Migration log saved to migration_log.xlsx")
        
if __name__ == "__main__":
    migrate_all()

