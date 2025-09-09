import os
from dotenv import load_dotenv
import re
import time
import json
import html
import mimetypes
from datetime import datetime, timezone
import requests
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
from requests.auth import HTTPBasicAuth
from bs4 import BeautifulSoup
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

# Work item type mapping (ADO -> Jira)
WORKITEM_TYPE_MAP = {
    "Epic": "Epic",
    "Task": "Task",
    "Issue": "Issue"  
}

# Priority mapping (ADO int -> Jira priority name)
PRIORITY_MAP = {
    1: "Highest", 
    2: "High", 
    3: "Medium",
    4: "Low"}

# ADO State -> Jira Status mapping
STATE_MAP = {
    "To Do": "To Do",
    "Doing": "In Progress",
    "Done": "Done"
}


# Optional (Not Configured yet): ADO email -> Jira accountId map
USER_MAP: Dict[str, str] = {
        "naadirasahar.n@cprime.com": "712020:d1b1f0d1-8e61-40a0-94f3-79e4c076f878",

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

def convert_ado_datetime(ado_datetime_str):
    if not ado_datetime_str:
        return None
    try:
        # Parse ISO 8601 with timezone awareness (e.g., 2025-09-24T10:00:00Z)
        dt = datetime.strptime(ado_datetime_str, "%Y-%m-%dT%H:%M:%SZ")
        dt = dt.replace(tzinfo=timezone.utc)  # explicitly set UTC
        result=dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        print(result,"uiopl")
        return result
    except ValueError:
        pass
    try:
        # Parse DD/MM/YYYY HH:MM
        dt = datetime.strptime(ado_datetime_str, "%d/%m/%Y %H:%M")
        result=dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        print("yuiop")
        return result
    except ValueError:
        pass
    try:
        # Parse DD/MM/YYYY
        dt = datetime.strptime(ado_datetime_str, "%d/%m/%Y")
        formatted = dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        print(formatted,"uiop")  # ✅ print actual value
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
    url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/wiql?api-version=7.0"
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
    r = requests.post(url, auth=jira_auth(), headers=headers, json={"fields": fields})
    if r.status_code == 201:
        key = r.json().get("key")
        log(f"✅ Created {key}")
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
    for element in soup.find_all(["div", "p", "a", "img"]):
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
                # No images inside — convert the block text
                text = element.get_text("\n", strip=True).strip()
                if text:
                    # If the block contains links, convert them to marks by processing anchors
                    # Simple approach: if anchors exist, create a paragraph per anchor/text piece.
                    if element.find("a"):
                        for part in element.find_all(["a"]):
                            href = part.get("href", "").strip()
                            label = part.get_text(strip=True) or href
                            if href and href not in seen_links:   # ✅ prevent duplicates
                                seen_links.add(href)
                                print(f"  🔗 New link from <p/div>: {href}")
                                adf_content.append({
                                    "type": "paragraph",
                                    "content": [{
                                        "type": "text",
                                        "text": label,
                                        "marks": [{"type": "link", "attrs": {"href": href}}]
                                    }]
                                })
                            else:
                                print(f"  ⚠️ Skipped duplicate link in <p/div>: {href}")
                    else:
                        print(f"  ✏️ Plain text block: {text}")
                        adf_content.append({"type": "paragraph", "content": [{"type": "text", "text": text}]})

        elif element.name == "a":
            href = element.get("href", "").strip()
            label = element.get_text(strip=True) or href
            if href and href not in seen_links:   # ✅ avoid duplicates
                seen_links.add(href)
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
            if src and ATTACH_URL_SUBSTR in src:
                filename = parse_qs(urlparse(src).query or "").get("fileName", ["embedded.png"])[0]

                local_file = download_images_to_ado_attachments(src)
                if not local_file:
                    continue

                upload = jira_upload_attachment(issue_key, local_file)
                if not upload or not upload.get("mediaId"):
                    continue

                # ✅ Only embed the media, no extra text
                adf_content.append({
                    "type": "mediaSingle",
                    "content": [
                        {
                            "type": "media",
                            "attrs": {
                                "type": "file",
                                "id": upload["mediaId"],
                                "collection": "jira-attachments"
                            }
                        }
                    ]
                })

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
            adf_content = [{"type": "paragraph", "content": [{"type": "text", "text": fallback_text}]}]

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

  
def build_jira_fields_from_ado(wi: Dict) -> Dict:
    f = wi.get("fields", {})
    summary = f.get("System.Title", "No Title")
    raw_desc = f.get("System.Description", "")
    desc_text = clean_html_to_text(raw_desc)

    ado_type = f.get("System.WorkItemType", "Task")
    jira_issuetype = WORKITEM_TYPE_MAP.get(ado_type, "Task")

    tags = f.get("System.Tags", "")
    labels: List[str] = []
    if tags:
        parts = re.split(r"[;,]", tags)
        labels = [p.strip().replace(" ", "-") for p in parts if p.strip()]

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

    # Save original ADO state for post-creation transition
    ado_state = f.get("System.State", "New")
    print(f.get("Microsoft.VSTS.Scheduling.StartDate"))
    print(f.get("Microsoft.VSTS.Scheduling.TargetDate"))
    fields: Dict = {
        "project": {"key": JIRA_PROJECT_KEY},
        "summary": summary,
        "issuetype": {"name": jira_issuetype},
        "description" : to_adf_doc("Temp placeholder"), # set placeholder first

        "labels": labels,
        
       "customfield_10443": convert_ado_datetime(
        f.get("Microsoft.VSTS.Scheduling.StartDate", "")
        ),

        "customfield_10585": convert_ado_datetime(
        f.get("Microsoft.VSTS.Scheduling.TargetDate", "")
        ),
        }
    
    if jira_priority_name:
        fields["priority"] = {"name": jira_priority_name}

    account_id = get_jira_account_id_for_email(assignee_email)
    print(f"🔎 ADO assignee email: {assignee_email}")
    print(f"🔎 Jira accountId mapped: {account_id}")
    
    if account_id:
        fields["assignee"] = {"id": account_id}

    tshirt_size = f.get("Custom.TShirtsize")
    print(tshirt_size)
    if tshirt_size:
        fields["customfield_10584"] = {"value": tshirt_size}

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
    url = f"https://one-atlas-mzvp.atlassian.net/rest/api/2/issue/{issue_key}/comment"
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
        "SELECT [System.Id] FROM WorkItems "
        "WHERE [System.TeamProject] = @project "
        "ORDER BY [System.Id] ASC"
    )
    ids = ado_wiql_all_ids(wiql)
    if not ids:
        log("No work items found.")
        return

    log(f"📌 Found {len(ids)} work items.")

    # -------------------------------
    # 🔹 ADD BATCH CONTROL HERE
    # -------------------------------
    START_INDEX = 0       # change for next run (0, 10000, 20000…)
    MAX_TO_PROCESS = 10 # how many to migrate this run

    ids = ids[START_INDEX:START_INDEX + MAX_TO_PROCESS]
    log(f"📌 Processing {len(ids)} work items (from index {START_INDEX}) in this run.")
    # -------------------------------

    for batch in chunked(ids, WIQL_PAGE_SIZE):
        time.sleep(SLEEP_BETWEEN_CALLS)
        workitems = ado_get_workitems_by_ids(batch)
        workitems.sort(key=lambda w: w.get("id", 0))
        log(f"➡️  Processing batch of {len(workitems)}")

        for wi in workitems:
            wi_id = int(wi.get("id"))
            wi_id_str = str(wi_id)
            log(f"--- ADO #{wi_id_str} ---")

            if wi_id_str in mapping:
                log(f"   ⚠️ Already migrated as {mapping[wi_id_str]}, skipping")
                continue

            # 1) Create Jira issue
            fields = build_jira_fields_from_ado(wi)
            issue_key = jira_create_issue(fields)

            raw_desc = wi.get("fields", {}).get("System.Description", "")
            if raw_desc:
                desc_adf = process_description_to_adf(issue_key, raw_desc)
                base = clean_base(JIRA_URL)
                url = f"{base}/rest/api/3/issue/{issue_key}"
                payload = {"fields": {"description": desc_adf}}
                headers = {"Content-Type": "application/json"}
                r = requests.put(url, auth=jira_auth(), headers=headers, json=payload)
                if r.status_code in (200, 204):
                    log(f"✅ Updated description for {issue_key} with inline images")
                else:
                    log(f"⚠️ Failed to update description for {issue_key}: {r.status_code} {r.text}")

            if not issue_key:
                continue

            # Save mapping ASAP
            mapping[wi_id_str] = issue_key
            with open(MAPPING_FILE, "w") as f:
                json.dump(mapping, f, indent=2)

            # Transition to mapped status
            ado_state = wi.get("fields", {}).get("System.State", "New")
            jira_transition_issue(issue_key, ado_state)

            # 2) Comments
            downloaded_files = []
            comments = ado_get_comments(wi_id)
            for c in reversed(comments):
                # print(c)
                html_text = c.get("text") or c.get("renderedText") or ""

                comment_text = c.get("text") or c.get("renderedText") or ""
                created_date = c.get("createdDate")
                author = (c.get("createdBy") or {}).get("displayName", "Unknown User")

                 # Format the timestamp nicely (e.g., "22 Aug 2025 at 13:50")
                try:
                    dt = datetime.strptime(created_date, "%Y-%m-%dT%H:%M:%S.%fZ")
                    created_str = dt.strftime("%d %b %Y at %H:%M")
                except Exception:
                    created_str = created_date

                # # prepend metadata into the comment body
                # meta_line = f"Originally commented by {author} on {created_str}\n\n"
                # body_with_meta = f"{meta_line}{comment_text}"

                # plain_text = clean_html_to_jira_format(issue_key, body_with_meta)

                plain_text=clean_html_to_jira_format(issue_key,html_text) 
                image_urls = re.findall(r'<img[^>]+src="([^"]+)"', html_text)

            

                print(html_text,"htmltext",plain_text,"plain_text",image_urls,"imageurl")
                if plain_text != " ":

                    if plain_text and not image_urls:
                        print("case-1")
                        body = plain_text
                        jira_add_comment(issue_key,body)

                    # case 2: image only
                    elif not plain_text and image_urls:
                        print("case 2")
                        for i in image_urls:
                                local_file = download_images_to_ado_attachments(i)
                                content_url = jira_upload_attachment(issue_key, local_file)
                                jira_upload_attachment_as_comment(issue_key, content_url,plain_text)
                    # case 3: text + image
                    else:
                        print("case 3")
                        for i in image_urls:
                            local_file = download_images_to_ado_attachments(i)
                            content_url=jira_upload_attachment(issue_key, local_file)  
                            jira_upload_attachment_as_comment(issue_key, content_url,plain_text)
                else:
                    continue
        
    log("🎉 Migration completed.")
    for file in os.listdir("ado_attachments"):
        try:
            os.remove(os.path.join("ado_attachments", file))
        except Exception as e:
            print(f"Failed to delete {file}: {e}")


if __name__ == "__main__":
    migrate_all()


