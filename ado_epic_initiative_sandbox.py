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
from bs4 import NavigableString, Tag
from typing import Dict, List, Tuple, Set

load_dotenv()

# ============================================================================
# INTEGRATED TABLE CONVERSION FUNCTIONS
# ============================================================================

def expand_table_to_grid(table_elem):
    """
    Expand an HTML table with rowspan/colspan into a normalized 2D grid.
    Each cell is a tuple: ('origin', td, orig_row, orig_col) for the real cell,
    or ('span', td, orig_row, orig_col) for cells covered by a span.
    None means the cell position is completely empty/missing.
    """
    all_trs = table_elem.find_all('tr')
    grid = []

    for row_idx, tr in enumerate(all_trs):
        while len(grid) <= row_idx:
            grid.append([])

        col_cursor = 0
        for td in tr.find_all(['td', 'th']):
            # Skip columns already filled by a rowspan from a previous row
            while col_cursor < len(grid[row_idx]) and grid[row_idx][col_cursor] is not None:
                col_cursor += 1

            rowspan = int(td.get('rowspan', 1))
            colspan = int(td.get('colspan', 1))

            for r in range(rowspan):
                for c in range(colspan):
                    ri = row_idx + r
                    ci = col_cursor + c
                    while len(grid) <= ri:
                        grid.append([])
                    while len(grid[ri]) <= ci:
                        grid[ri].append(None)
                    if r == 0 and c == 0:
                        grid[ri][ci] = ('origin', td, row_idx, col_cursor)
                    else:
                        grid[ri][ci] = ('span', td, row_idx, col_cursor)

            col_cursor += colspan

    return grid

def _parse_html_table_to_adf(table_elem) -> Dict:
    """
    Convert a BeautifulSoup table element to a Jira ADF table node.
    Correctly handles rowspan/colspan using grid expansion so spanned
    cell content always lands in the right column.
    """
    grid = expand_table_to_grid(table_elem)
    if not grid:
        return None

    num_cols = max(len(row) for row in grid) if grid else 0
    # Normalize all rows to the same width
    for row in grid:
        while len(row) < num_cols:
            row.append(None)

    # Determine which columns have any real (origin) content
    col_has_content = {c: False for c in range(num_cols)}
    for row in grid:
        for c, cell in enumerate(row):
            if cell and cell[0] == 'origin' and cell[1].get_text(strip=True):
                col_has_content[c] = True

    real_cols = [c for c in range(num_cols) if col_has_content.get(c, False)]
    if not real_cols:
        real_cols = list(range(num_cols))

    rendered_origins = set()
    table_rows = []

    for row in grid:
        # Skip rows where every real column is either empty or a
        # already-rendered span with no new content to show
        row_has_visible = False
        for c in real_cols:
            cell = row[c] if c < len(row) else None
            if cell is None:
                continue
            kind, td, orig_r, orig_c = cell
            if kind == 'origin' and td.get_text(strip=True):
                row_has_visible = True
                break
            if kind == 'span' and (orig_r, orig_c) not in rendered_origins:
                if td.get_text(strip=True):
                    row_has_visible = True
                    break

        if not row_has_visible:
            # Mark any unrendered spans as rendered so they don't leak later
            for c in real_cols:
                cell = row[c] if c < len(row) else None
                if cell and cell[0] == 'span':
                    rendered_origins.add((cell[2], cell[3]))
            continue

        is_header_row = any(
            row[c][1].name == 'th'
            for c in real_cols
            if c < len(row) and row[c] and row[c][0] in ('origin', 'span')
        )

        row_cells = []
        for c in real_cols:
            cell = row[c] if c < len(row) else None
            cell_type = "tableHeader" if is_header_row else "tableCell"

            if cell is None:
                row_cells.append({
                    "type": cell_type,
                    "content": [{"type": "paragraph", "content": []}]
                })
                continue

            kind, td, orig_r, orig_c = cell
            origin_key = (orig_r, orig_c)

            if kind == 'origin':
                rendered_origins.add(origin_key)
                cell_content = _extract_cell_content(td)
            else:  # 'span'
                if origin_key not in rendered_origins:
                    rendered_origins.add(origin_key)
                    cell_content = _extract_cell_content(td)
                else:
                    cell_content = [{"type": "text", "text": ""}]

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
        return process_description_to_adf(issue_key, raw_html)

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
                            nodes_copy = nodes.copy()
                            nodes.clear()
                            nodes.extend(nodes_copy)
                            nodes.append({"__block__": "codeBlock", "text": raw})
                    else:
                        nodes.extend(make_inline_nodes(child))
                elif name == "img":
                    src = (child.get("src") or "").strip()
                    if src and ATTACH_URL_SUBSTR in src:
                        local_file = download_images_to_ado_attachments(src)
                        if local_file:
                            upload = jira_upload_attachment(issue_key, local_file)
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
        """Delegate to the shared rowspan-aware table parser."""
        return _parse_html_table_to_adf(table_elem)

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
                local_file = download_images_to_ado_attachments(src)
                if local_file:
                    upload = jira_upload_attachment(issue_key, local_file)
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
                            lf = download_images_to_ado_attachments(src)
                            if lf:
                                up = jira_upload_attachment(issue_key, lf)
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
# END OF NEW TABLE CONVERSION FUNCTIONS
# ============================================================================

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

# User-Credentials
Email = os.getenv("EMAIL")
JIRA_ACCOUNT_ID = os.getenv("JIRA_ACCOUNT_ID")

# -------------------
# CSV-BASED USER MAP
# -------------------
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

WORKITEM_TYPE_MAP = {
    # "Bug": "Bug",
    # "Defect": "Defect",
    "Epic": "Initiative",
    # "Feature": "Feature",
    # "Hotfix": "Hotfix",
    # "Issue": "Issue",
    # "Joes Test": "Joes Test",
    # "Portfolio Epic": "Portfolio Epic",
    # "Post Lockdown": "Post Lockdown",
    # "Request": "Request",
    # "RIDA (disabled)": "RIDA (disabled)",
    # "Risk (disabled)": "Risk (disabled)",
    # "Task": "Task",
    # "Test Case": "Epic",
    # "Test Plan": "Test Plan",
    # "Test Suite": "Test Suite",
    # "User Story": "User Story"
}

PRIORITY_MAP = {
    1: "P1 - Critical",
    2: "P2 - High",
    3: "P3 - Medium",
    4: "P4 - Low"
}

STATE_MAP = {
    "New": "New",
    "Closed": "Done",
    "In Progress": "Build"
}

WIQL_PAGE_SIZE = 200
SLEEP_BETWEEN_CALLS = 0.2
MAPPING_FILE = "ado_jira_mapping.json"
ATTACH_DIR = "ado_attachments"
ATTACH_URL_SUBSTR = "/_apis/wit/attachments/"

MAX_RETRIES = 4
RETRY_BACKOFF_BASE = 2
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


# ---------- Retry helper ----------
def api_call_with_retry(fn, *args, label: str = "API call", **kwargs):
    last_exc = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = fn(*args, **kwargs)
            if response.status_code in RETRYABLE_STATUS_CODES:
                wait = RETRY_BACKOFF_BASE ** attempt
                retry_after = response.headers.get("Retry-After")
                if retry_after:
                    try:
                        wait = max(wait, int(retry_after))
                    except ValueError:
                        pass
                log(f"   ⚠️ {label} → HTTP {response.status_code}. "
                    f"Attempt {attempt}/{MAX_RETRIES}. Retrying in {wait}s...")
                time.sleep(wait)
                continue
            return response
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout) as exc:
            last_exc = exc
            wait = RETRY_BACKOFF_BASE ** attempt
            log(f"   ⚠️ {label} → {type(exc).__name__}. "
                f"Attempt {attempt}/{MAX_RETRIES}. Retrying in {wait}s...")
            time.sleep(wait)

    if last_exc:
        raise last_exc
    raise RuntimeError(f"{label} failed after {MAX_RETRIES} attempts.")


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


# ---------- ADO fetch (with retry) ----------
def ado_wiql_all_ids(query: str) -> List[int]:
    print(query, "")
    url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/wiql?api-version=7.1-preview.2"
    r = api_call_with_retry(
        requests.post, url,
        json={"query": query}, auth=ado_auth(),
        label="ADO WIQL query"
    )
    print("Status:", r.status_code)
    print("Response text:", r.text[:500])
    r.raise_for_status()
    items = r.json().get("workItems", [])
    return [wi["id"] for wi in items]

def ado_get_workitems_by_ids(ids: List[int]) -> List[Dict]:
    if not ids:
        return []
    url = (f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/workitems"
           f"?api-version=7.0&$expand=all&ids={','.join(map(str, ids))}")
    r = api_call_with_retry(
        requests.get, url,
        auth=ado_auth(),
        label=f"ADO get workitems {ids[:3]}..."
    )
    r.raise_for_status()
    print(r.json().get("value", []), "Issue Detail from AzureDevops")
    return r.json().get("value", [])

def ado_get_comments(wi_id: int) -> List[Dict]:
    url = (f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/workItems"
           f"/{wi_id}/comments?api-version=7.0-preview.3")
    try:
        r = api_call_with_retry(
            requests.get, url,
            auth=ado_auth(),
            label=f"ADO get comments #{wi_id}"
        )
        if r.status_code == 200:
            return r.json().get("comments", [])
        else:
            log(f"   ⚠️ Comments fetch failed for {wi_id}: {r.status_code} {r.text}")
            return []
    except Exception as e:
        log(f"   ⚠️ Comments fetch exception for {wi_id}: {e}")
        return []

def ado_get_attachments_from_relations(wi: Dict) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for rel in (wi.get("relations") or []):
        if rel.get("rel") == "AttachedFile":
            url = rel.get("url")
            name = (rel.get("attributes") or {}).get("name") or "attachment"
            out.append((url, name))
    return out


# --- Inline attachments parsing ---
IMG_SRC_RE = re.compile(r'(?is)<img[^>]+src=["\']([^"\']+)["\']')
HREF_RE    = re.compile(r'(?is)<a[^>]+href=["\']([^"\']+)["\']')

# ADO GUID regex — used for mention resolution
_ADO_GUID_RE = re.compile(
    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
)

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


# ---------- Attachment download/upload (with retry) ----------
def _with_download_params(u: str, api_version: str = "7.0") -> str:
    p = urlparse(u)
    q = parse_qs(p.query)
    q = {k: v for k, v in q.items()}
    if "api-version" not in q:
        q["api-version"] = [api_version]
    if "download" not in q:
        q["download"] = ["true"]
    new_q = urlencode(
        {k: v[0] if isinstance(v, list) and len(v) == 1 else v for k, v in q.items()},
        doseq=True
    )
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))

def ado_download_attachment(att_url: str, desired_filename: str) -> str:
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
            r = api_call_with_retry(
                requests.get, url_try,
                auth=ado_auth(), headers=headers,
                stream=True, allow_redirects=True,
                label=f"ADO download attachment attempt {idx}"
            )
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

def jira_upload_attachment(issue_key: str, file_path: str) -> dict:
    if not file_path or not os.path.exists(file_path):
        return None

    base = clean_base(JIRA_URL)
    url = f"{base}/rest/api/3/issue/{issue_key}/attachments"
    headers = {"X-Atlassian-Token": "no-check"}

    try:
        with open(file_path, "rb") as fh:
            files = {
                "file": (
                    os.path.basename(file_path), fh,
                    mimetypes.guess_type(file_path)[0] or "application/octet-stream"
                )
            }
            r = api_call_with_retry(
                requests.post, url,
                headers=headers, auth=jira_auth(), files=files,
                label=f"Jira upload attachment to {issue_key}"
            )
    except Exception as e:
        log(f"   ⚠️ Upload attachment exception for {file_path}: {e}")
        return None

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
    log(f"Media ID: {media_id}, id: {numeric_id}, filename: {filename}, Content: {content_url}")
    return {
        "mediaId": media_id,
        "id": numeric_id,
        "filename": filename,
        "content": content_url,
        "raw": info
    }


# ---------- Jira issue + comments (with retry) ----------
def jira_create_issue(fields: Dict) -> str:
    base = clean_base(JIRA_URL)
    url = f"{base}/rest/api/3/issue"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    print(fields, "lop")
    try:
        r = api_call_with_retry(
            requests.post, url,
            auth=jira_auth(), headers=headers, json={"fields": fields},
            label="Jira create issue"
        )
        if r.status_code == 201:
            key = r.json().get("key")
            log(f"✅ Created {key}")
            print(steps_payload, "iop")
            return key
        else:
            log(f"❌ Issue create failed: {r.status_code} {r.text}")
            return ""
    except Exception as e:
        log(f"❌ Issue create exception: {e}")
        return ""

def jira_add_comment(issue_key: str, text: str):
    if not text:
        return
    base = clean_base(JIRA_URL)
    url = f"{base}/rest/api/3/issue/{issue_key}/comment"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    payload = {"body": to_adf_doc(text)}
    try:
        r = api_call_with_retry(
            requests.post, url,
            auth=jira_auth(), headers=headers, json=payload,
            label=f"Jira add comment to {issue_key}"
        )
        if r.status_code not in (200, 201):
            log(f"   ⚠️ Add comment failed: {r.status_code} {r.text}")
    except Exception as e:
        log(f"   ⚠️ Add comment exception: {e}")


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


def process_description_to_adf(issue_key: str, raw_html: str) -> dict:
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
            adf_content.append({
                "type": "paragraph",
                "content": [{"type": "text", "text": src, "marks": [{"type": "link", "attrs": {"href": src}}]}]
            })

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
        fallback_text = re.sub(r"<[^>]+>", " ", raw_html)
        fallback_text = html.unescape(fallback_text).strip()
        if fallback_text:
            adf_content = [{"type": "paragraph", "content": [make_text_node(fallback_text)]}]

    return {"type": "doc", "version": 1, "content": adf_content}


def process_description_with_attachments(issue_key: str, raw_html: str) -> Dict:
    if not raw_html:
        return to_adf_doc("")
    soup = BeautifulSoup(raw_html, "html.parser")
    for img in soup.find_all("img"):
        src = img.get("src")
        if src and ATTACH_URL_SUBSTR in src:
            filename = parse_qs(urlparse(src).query or "").get("fileName", ["embedded.png"])[0]
            local_file = download_images_to_ado_attachments(src)
            content_url = jira_upload_attachment(issue_key, local_file)
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


def download_and_upload_reprosteps_images(issue_key: str, repro_html: str) -> Dict[str, str]:
    attachment_map = {}
    if not repro_html:
        return attachment_map
    soup = BeautifulSoup(repro_html, "html.parser")
    imgs = soup.find_all("img")
    for img in imgs:
        src = img.get("src")
        if src and ATTACH_URL_SUBSTR in src and src not in attachment_map:
            filename = parse_qs(urlparse(src).query or "").get("fileName", ["attachment.png"])[0]
            local_file = ado_download_attachment(src, filename)
            if not local_file:
                log(f"   ⚠️ Failed to download: {src}")
                continue
            upload_info = jira_upload_attachment(issue_key, local_file)
            if upload_info and upload_info.get("id"):
                attachment_map[src] = upload_info["id"]
                log(f"   ✅ Mapped: {filename} → Jira ID {upload_info['id']}")
            else:
                log(f"   ⚠️ Failed to upload: {filename}")
    return attachment_map


def convert_ado_reprosteps_to_jira_adf(
    html_input: str,
    attachment_map: Dict[str, str] = None,
    issue_key: str = None
) -> Dict:
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
            doc_content.append({
                "type": "table",
                "attrs": {"isNumberColumnEnabled": False, "layout": "default"},
                "content": rows
            })
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

    log_to_excel(wi_id, None, "Build Fields", "Started", "Building Jira fields from ADO")

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

    ado_type = f.get("System.WorkItemType", "Epic")
    jira_issuetype = WORKITEM_TYPE_MAP.get(ado_type, "Initiative")
    log_to_excel(wi_id, None, "Issue Type", "Success", f"ADO: {ado_type} → Jira: {jira_issuetype}")

    tags = f.get("System.Tags", "")
    labels: List[str] = []
    if tags:
        parts = re.split(r"[;,]", tags)
        labels = [p.strip().replace(" ", "-") for p in parts if p.strip()]
        log_to_excel(wi_id, None, "Labels", "Success", f"Mapped {len(labels)} labels")
    else:
        log_to_excel(wi_id, None, "Labels", "Skipped", "No tags in ADO")

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
            fields["customfield_12092"] = convert_ado_datetime(created_date)
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
            fields["customfield_14581"] = float(priority_rank)
            log_to_excel(wi_id, None, "Priority Rank", "Success", f"Value: {priority_rank}")
        except ValueError:
            log_to_excel(wi_id, None, "Priority Rank", "Error", f"Invalid value: {priority_rank}")
    else:
        log_to_excel(wi_id, None, "Priority Rank", "Skipped", "No priority rank in ADO")

    # Go Live Date
    go_live_date = f.get("Custom.GoLiveDate")
    if go_live_date:
        try:
            fields["customfield_11907"] = convert_ado_datetime(go_live_date)
            log_to_excel(wi_id, None, "Go Live Date", "Success", f"Mapped: {go_live_date}")
        except Exception as e:
            log_to_excel(wi_id, None, "Go Live Date", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Go Live Date", "Skipped", "No go live date in ADO")

    # Start Date
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
    if tshirt_size:
        try:
            fields["customfield_14396"] = {"value": tshirt_size}
            log_to_excel(wi_id, None, "T-Shirt Size", "Success", f"Value: {tshirt_size}")
        except Exception as e:
            log_to_excel(wi_id, None, "T-Shirt Size", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "T-Shirt Size", "Skipped", "No t-shirt size in ADO")

    # Latest Release Version
    latest_release_version = f.get("Custom.LatestReleaseVersion")
    if latest_release_version:
        try:
            fields["customfield_12018"] = to_adf_doc(str(latest_release_version))
            log_to_excel(wi_id, None, "Release Version", "Success", f"Value: {latest_release_version}")
        except Exception as e:
            log_to_excel(wi_id, None, "Release Version", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Release Version", "Skipped", "No release version in ADO")

    # Latest Release
    latest_release = f.get("Custom.LatestRelease")
    if latest_release:
        try:
            fields["customfield_12037"] = to_adf_doc(str(latest_release))
            log_to_excel(wi_id, None, "Latest Release", "Success", f"Value: {latest_release}")
        except Exception as e:
            log_to_excel(wi_id, None, "Latest Release", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Latest Release", "Skipped", "No latest release in ADO")

    # Custom Status
    custom_status = f.get("Custom.Status")
    if custom_status:
        try:
            fields["customfield_12010"] = {"value": custom_status}
            log_to_excel(wi_id, None, "Custom Status", "Success", f"Value: {custom_status}")
        except Exception as e:
            log_to_excel(wi_id, None, "Custom Status", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Custom Status", "Skipped", "No custom status in ADO")

    # Value Stream
    value_stream = f.get("Custom.ValueStream")
    if value_stream:
        try:
            fields["customfield_11636"] = {"value": value_stream}
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
            fields["customfield_14397"] = [{"value": p} for p in parts]
            log_to_excel(wi_id, None, "Customer Name", "Success", f"Mapped {len(parts)} values")
        except Exception as e:
            log_to_excel(wi_id, None, "Customer Name", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Customer Name", "Skipped", "No customer name in ADO")

    # Deliverable Type
    deliverable_type = f.get("Custom.DeliverableType")
    if deliverable_type:
        try:
            fields["customfield_14398"] = {"value": deliverable_type}
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

    # CAP Required
    cap_required = f.get("Custom.CAPRequired")
    if cap_required:
        try:
            fields["customfield_14399"] = {"value": cap_required}
            log_to_excel(wi_id, None, "CAP Required", "Success", f"Value: {cap_required}")
        except Exception as e:
            log_to_excel(wi_id, None, "CAP Required", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "CAP Required", "Skipped", "No CAP required in ADO")

    # Priority Level
    priority_level = f.get("Custom.PriorityLevel")
    if priority_level:
        try:
            fields["customfield_14400"] = {"value": priority_level}
            log_to_excel(wi_id, None, "Priority Level", "Success", f"Value: {priority_level}")
        except Exception as e:
            log_to_excel(wi_id, None, "Priority Level", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Priority Level", "Skipped", "No priority level in ADO")

    # Strategic Theme
    strategic_theme = f.get("Custom.StrategicTheme")
    if strategic_theme:
        try:
            fields["customfield_12285"] = {"value": strategic_theme}
            log_to_excel(wi_id, None, "Strategic Theme", "Success", f"Value: {strategic_theme}")
        except Exception as e:
            log_to_excel(wi_id, None, "Strategic Theme", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Strategic Theme", "Skipped", "No strategic theme in ADO")

    # Module Type
    module_type = f.get("Custom.ModuleType")
    if module_type:
        try:
            fields["customfield_14401"] = [{"value": module_type}]
            log_to_excel(wi_id, None, "Module Type", "Success", f"Value: {module_type}")
        except Exception as e:
            log_to_excel(wi_id, None, "Module Type", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Module Type", "Skipped", "No module type in ADO")

    # Horizon
    horizon = f.get("Custom.Horizon")
    if horizon:
        try:
            fields["customfield_14402"] = {"value": horizon}
            log_to_excel(wi_id, None, "Horizon", "Success", f"Value: {horizon}")
        except Exception as e:
            log_to_excel(wi_id, None, "Horizon", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Horizon", "Skipped", "No horizon in ADO")

    # Value Drivers
    value_drivers = f.get("Custom.ValueDrivers")
    if value_drivers:
        try:
            fields["customfield_14403"] = {"value": value_drivers}
            log_to_excel(wi_id, None, "Value Drivers", "Success", f"Value: {value_drivers}")
        except Exception as e:
            log_to_excel(wi_id, None, "Value Drivers", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Value Drivers", "Skipped", "No value drivers in ADO")

    # Business Objective
    business_objective = f.get("Custom.BusinessObjectiveOKR")
    if business_objective:
        try:
            fields["customfield_14404"] = {"value": business_objective}
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
            fields["customfield_12220"] = [{"value": p} for p in parts]
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
    if wid:
        try:
            ado_base = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}"
            ado_ui_link = f"{ado_base}/_workitems/edit/{wid}"
            fields["customfield_14407"] = ado_ui_link
            print("ADO WorkItem Link:", ado_ui_link)
            log_to_excel(wi_id, None, "ADO Work Item Link", "Success", f"Link: {ado_ui_link}")
        except Exception as e:
            log_to_excel(wi_id, None, "ADO Work Item Link", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "ADO Work Item Link", "Warning", "No System.Id found")

    # Area Path (select-list)
    area_path = f.get("System.AreaPath")
    if area_path:
        fields["customfield_14406"] = {"value": area_path}
        log_to_excel(wi_id, None, "Area Path", "Success", area_path)

    # # Area Path
    # area = f.get("System.AreaPath")
    # if area:
    #     try:
    #         fields["customfield_11601"] = str(area)
    #         log_to_excel(wi_id, None, "Area Path", "Success", f"Value: {area}")
    #     except Exception as e:
    #         log_to_excel(wi_id, None, "Area Path", "Error", str(e)[:100])
    # else:
    #     log_to_excel(wi_id, None, "Area Path", "Skipped", "No area path in ADO")

    # Iteration Path (Single Select)
    iteration = f.get("System.IterationPath")
    if iteration:
        fields["customfield_14405"] = {"value": iteration}
        log_to_excel(wi_id, None, "Iteration Path", "Success", iteration)

    # Reason
    reason = f.get("System.Reason")
    if reason:
        try:
            fields["customfield_14582"] = str(reason)
            log_to_excel(wi_id, None, "Reason", "Success", f"Value: {reason}")
        except Exception as e:
            log_to_excel(wi_id, None, "Reason", "Error", str(e)[:100])
    else:
        log_to_excel(wi_id, None, "Reason", "Skipped", "No reason in ADO")

    log_to_excel(wi_id, None, "Build Fields", "Completed", f"Built {len(fields)} fields successfully")
    return fields


OUTPUT_DIR = "ado_attachments"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def jira_transition_issue(issue_key: str, ado_state: str):
    target_status = STATE_MAP.get(ado_state)
    if not target_status:
        return

    base = clean_base(JIRA_URL)
    url = f"{base}/rest/api/3/issue/{issue_key}/transitions"
    try:
        r = api_call_with_retry(
            requests.get, url,
            auth=jira_auth(), headers={"Accept": "application/json"},
            label=f"Jira get transitions {issue_key}"
        )
        if r.status_code != 200:
            log(f"⚠️ Failed to fetch transitions for {issue_key}")
            return
    except Exception as e:
        log(f"⚠️ Transition fetch exception for {issue_key}: {e}")
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

    try:
        r = api_call_with_retry(
            requests.post, url,
            auth=jira_auth(),
            headers={"Content-Type": "application/json"},
            json={"transition": {"id": transition_id}},
            label=f"Jira transition {issue_key} → {target_status}"
        )
        if r.status_code in (200, 204):
            log(f"✅ {issue_key} transitioned to '{target_status}'")
        else:
            log(f"⚠️ Failed to transition {issue_key} -> {target_status}: {r.status_code} {r.text}")
    except Exception as e:
        log(f"⚠️ Transition exception for {issue_key}: {e}")


def download_images_to_ado_attachments(url):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if "fileName" in query:
        filename = query["fileName"][0]
    else:
        filename = os.path.basename(parsed.path)

    output_file = os.path.join(OUTPUT_DIR, filename)
    try:
        response = api_call_with_retry(
            requests.get, url,
            auth=HTTPBasicAuth("", ADO_PAT), stream=True,
            label=f"ADO download image {filename}"
        )
        if response.status_code == 200:
            with open(output_file, "wb") as f:
                for chunk in response.iter_content(1024):
                    f.write(chunk)
            print(f"✅ Image downloaded as {output_file}")
            return output_file
        else:
            print(f"❌ Failed: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"❌ Download image exception: {e}")
    return None


def jira_add_comment_for_link(issue_key: str, body: str):
    url = f"{JIRA_URL}/rest/api/2/issue/{issue_key}/comment"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    auth = HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN)
    try:
        response = api_call_with_retry(
            requests.post, url,
            headers=headers, auth=auth, json={"body": body},
            label=f"Jira add comment (link) to {issue_key}"
        )
        if response.status_code == 201:
            print(f"✅ Comment added to {issue_key}")
        else:
            print(f"❌ Failed to add comment: {response.status_code}, {response.text}")
    except Exception as e:
        print(f"❌ Add comment exception: {e}")


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
    r = api_call_with_retry(
        requests.get, url,
        auth=ado_auth(),
        label=f"ADO fetch workitem title #{wid}"
    )
    r.raise_for_status()
    data = r.json()
    title = data["fields"].get("System.Title", "ADO Work Item")
    wi_type = data["fields"].get("System.WorkItemType", "")
    return title, wi_type

def create_links_from_ado(wi, issue_key):
    relations = wi.get("relations", [])
    if not relations:
        print(f"No relations found for ADO work item → Jira {issue_key}")
        return

    base = clean_base(JIRA_URL)

    for rel in relations:
        try:
            url = rel.get("url")
            rel_type = rel.get("attributes", {}).get("name", "Related")

            if not url or url.startswith("vstfs:///"):
                print(f"Skipping artifact link for {issue_key}")
                continue
            if "_apis/wit/workItems" not in url:
                print(f"Skipping non-workitem link: {url}")
                continue

            wid = extract_wid(url)
            if not wid:
                print(f"Could not extract work item ID from {url}")
                continue

            title, _ = fetch_ado_workitem_title(wid)
            ado_ui_url = ado_api_to_ui_link(url)
            payload = {"object": {"url": ado_ui_url, "title": f"[{rel_type}] {wid} | {title}"}}
            link_url = f"{base}/rest/api/3/issue/{issue_key}/remotelink"

            r = api_call_with_retry(
                requests.post, link_url,
                json=payload, auth=jira_auth(),
                headers={"Content-Type": "application/json"},
                label=f"Jira create remote link {issue_key} ← {wid}"
            )
            if r.status_code in (200, 201):
                print(f"✔ Linked [{rel_type}] {wid} | {title} → Jira {issue_key}")
            else:
                print(f"✖ Failed linking {wid} → Jira {issue_key} | Status: {r.status_code} | {r.text}")
        except Exception as e:
            print(f"❌ Error while processing relation for Jira {issue_key} | URL: {url} | Error: {e}")


# ----------------------------
# Global migration log
# ----------------------------
migration_log: Dict[str, Dict] = {}

def log_to_excel(wi_id, issue_key, step, status, message):
    key = str(wi_id)
    if key not in migration_log:
        migration_log[key] = {"WorkItemID": wi_id, "IssueKey": issue_key or ""}
    if issue_key:
        migration_log[key]["IssueKey"] = issue_key
    migration_log[key][f"{step}_Status"] = status
    migration_log[key][f"{step}_Message"] = message
    print(f"{wi_id} | {issue_key or 'NA'} | {step} | {status} | {message}")


# ============================================================
# COMMENT HANDLING — full pipeline from Code 1
# ============================================================

# ---- ADO Identity resolution ----

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


# ---- GUID → Jira accountId map (loaded once from ado_guid_map.csv) ----

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
                # Skip separator rows (---|---|---)
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
    angle_triple = re.compile(
        r'<\[([^\]]+?)>?\]\([^\)]*?\)',
        re.DOTALL
    )

    def fix_angle_triple(m):
        display = m.group(1).rstrip('>').strip()
        if display.startswith('http'):
            return f'[{display}]({display})'
        return m.group(0)

    text = angle_triple.sub(fix_angle_triple, text)

    # Step 3: fix remaining title-escaped links: [text](url "title")
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
    if _looks_like_block_html(raw_text):
        return ("html", raw_text, raw_text)

    if comment_format == "markdown" and _looks_like_markdown(raw_text):
        return ("markdown", raw_text, rendered_text)

    if _looks_like_markdown(raw_text) and not _looks_like_html(raw_text):
        return ("markdown", raw_text, rendered_text)

    return ("plain", raw_text, rendered_text)


def _is_mention_link(tag) -> bool:
    """Detect if an <a> tag is an ADO @mention link."""
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


def _resolve_mention_to_text(tag) -> str:
    """
    Resolve an ADO mention <a> tag to a Jira mention string.
    Falls back to @DisplayName if no Jira account mapping found.
    """
    href = (tag.get("href") or "").strip()
    label = tag.get_text(strip=True) or ""

    # Try to map via email (mailto: links)
    if href.lower().startswith("mailto:"):
        email = href[7:].strip().lower()
        account_id = USER_MAP.get(email)
        if account_id:
            return f"[~accountId:{account_id}]"

    # Try to map via GUID in href or data-vss-mention
    for attr in ["data-vss-mention", "href"]:
        val = tag.get(attr, "")
        guids = _ADO_GUID_RE.findall(val)
        for guid in guids:
            guid_map = _get_ado_guid_map()
            acct = guid_map.get(guid.lower())
            if acct:
                return f"[~accountId:{acct}]"

    # Fall back: clean up display name
    clean_name = _ADO_GUID_RE.sub("", label)
    clean_name = clean_name.lstrip("@<").rstrip(">").strip()
    if not clean_name:
        if href.lower().startswith("mailto:"):
            clean_name = href[7:].split("@")[0].strip()
        if not clean_name:
            clean_name = "Unknown"
    return f"@{clean_name}"


def _parse_comment_html(html_text: str) -> List[Dict]:
    """
    Parse ADO comment HTML into a flat list of parts:
      {"kind": "text",  "value": "some text"}
      {"kind": "image", "src":   "https://..."}

    Handles: plain text, <br>, <p>, <div>, <a> links,
             @mention links, <img> tags (inline images).
    All content is collected in DOM order — no posting side-effects.
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

    def walk(node):
        if isinstance(node, NavigableString):
            txt = str(node)
            if txt:
                text_buf.append(txt)
            return

        if not hasattr(node, 'name') or node.name is None:
            return

        name = node.name.lower()

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
            if _is_mention_link(node):
                text_buf.append(_resolve_mention_to_text(node))
            else:
                if href:
                    text_buf.append(f"[{label}|{href}]")
                else:
                    text_buf.append(label)
            return

        if name == "br":
            text_buf.append("\n")
            return

        if name == "table":
            flush_text()
            log(f"   🔍 DEBUG: table handler hit, rows={len(node.find_all('tr'))}")  # add this
            tbl = _parse_html_table_to_adf(node)
            log(f"   🔍 DEBUG: tbl result = {tbl is not None}")  # add this
            if tbl:
                parts.append({"kind": "table_adf", "adf": tbl})
            return

        is_block = name in {"p", "div", "li", "ul", "ol",
                             "h1", "h2", "h3", "h4", "h5", "h6",
                             "blockquote", "tr", "td", "th"}
        if is_block:
            flush_text()
            for child in node.children:
                walk(child)
            flush_text()
            return

        for child in node.children:
            walk(child)

    for top_node in soup.contents:
        walk(top_node)
    flush_text()

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

def _has_table_parts(parts: List[Dict]) -> bool:
    return any(p["kind"] == "table_adf" for p in parts)


def build_comment_adf_with_tables(parts: List[Dict], image_url_map: Dict[str, str],
                                   meta_line: str) -> Dict:
    """Build full ADF doc for comments containing tables."""
    content = []
    content.append({
        "type": "paragraph",
        "content": [{"type": "text", "text": meta_line,
                     "marks": [{"type": "strong"}]}]
    })
    for p in parts:
        if p["kind"] == "text":
            txt = p["value"].strip()
            if txt:
                for line in re.split(r'\n{2,}', txt):
                    line = line.strip()
                    if line:
                        content.append({
                            "type": "paragraph",
                            "content": [{"type": "text", "text": line}]
                        })
        elif p["kind"] == "table_adf":
            content.append(p["adf"])
        elif p["kind"] in ("image", "image_local"):
            key = p.get("src") or p.get("path")
            jira_url = image_url_map.get(key)
            if jira_url:
                content.append({
                    "type": "paragraph",
                    "content": [{"type": "text", "text": jira_url,
                                 "marks": [{"type": "link",
                                            "attrs": {"href": jira_url}}]}]
                })
    return {"type": "doc", "version": 1, "content": content}

def process_comment_and_post(issue_key: str, comment: Dict, wi_id=None, comment_index: int = 0,
                              author: str = "Unknown", created_str: str = ""):
    """
    Process and post an ADO comment to Jira.
    Handles HTML/markdown format detection, inline image download+upload,
    URL deduplication, and @mention resolution.
    """
    meta_line = f"*Commented by {author} on {created_str}*"

    comment_format, raw_text, rendered_text = detect_comment_format(comment)

    log(f"   💬 Comment[{comment_index}]: format={comment_format}, has_content={bool(raw_text or rendered_text)}")

    # Empty comment — post meta-line only
    if not raw_text or not raw_text.strip():
        if not rendered_text or not rendered_text.strip():
            _post_single_comment(issue_key, meta_line, wi_id=wi_id, comment_index=comment_index)
            log_to_excel(wi_id, issue_key, f"Comment[{comment_index}]", "Success", "Meta-only (empty body)")
            return

    # Parse based on detected format
    if comment_format == "markdown":
        log(f"   🔍 Resolving mentions for comment {comment_index} (markdown)...")
        mention_map = _build_mention_map_from_comment(comment)
        parts = _parse_comment_markdown_improved(raw_text, mention_map)

    elif comment_format == "html":
        parts = _parse_comment_html(rendered_text or raw_text)
        log(f"   🔍 DEBUG parts kinds: {[p['kind'] for p in parts]}") 

    else:  # plain text — run through markdown improved for mention resolution
        log(f"   🔍 Resolving mentions for comment {comment_index} (plain)...")
        mention_map = _build_mention_map_from_comment(comment)
        parts = _parse_comment_markdown_improved(raw_text, mention_map)

    if not parts:
        _post_single_comment(issue_key, meta_line, wi_id=wi_id, comment_index=comment_index)
        log_to_excel(wi_id, issue_key, f"Comment[{comment_index}]", "Success", "Meta-only (no content)")
        return

    has_images = any(p["kind"] in ("image", "image_local") for p in parts)
    has_text = any(p["kind"] == "text" for p in parts)

    log(f"   📝 Comment[{comment_index}]: {len(parts)} parts | text={has_text} | images={sum(1 for p in parts if p['kind'] == 'image')}")

    # No images — post as plain text comment
    if not has_images:
        full_text = "\n\n".join(p["value"] for p in parts if p["kind"] == "text").strip()
        
        if _has_table_parts(parts):
            adf_body = build_comment_adf_with_tables(parts, {}, meta_line)
            comment_url = f"{clean_base(JIRA_URL)}/rest/api/3/issue/{issue_key}/comment"
            headers = {"Accept": "application/json", "Content-Type": "application/json"}
            r = api_call_with_retry(
                requests.post, comment_url,
                auth=jira_auth(), headers=headers, json={"body": adf_body},
                label=f"Jira post comment[{comment_index}] (ADF/table) to {issue_key}"
            )
            if r.status_code in (200, 201):
                log(f"   ✅ Comment[{comment_index}] posted with table")
                log_to_excel(wi_id, issue_key, f"Comment[{comment_index}]", "Success", "Table comment")
            else:
                log(f"   ❌ Comment[{comment_index}] failed: {r.status_code}")
                log_to_excel(wi_id, issue_key, f"Comment[{comment_index}]", "Failed", f"HTTP {r.status_code}")
            return
        
        body = f"{meta_line}\n\n{full_text}" if full_text else meta_line  # ← THIS LINE WAS MISSING
        _post_single_comment(issue_key, body, wi_id=wi_id, comment_index=comment_index)
        log_to_excel(wi_id, issue_key, f"Comment[{comment_index}]", "Success",
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

    # Build and post final comment body — use ADF (api/3) if tables present, else wiki (api/2)
    if _has_table_parts(parts):
        adf_body = build_comment_adf_with_tables(parts, image_url_map, meta_line)
        comment_url = f"{clean_base(JIRA_URL)}/rest/api/3/issue/{issue_key}/comment"
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        r = api_call_with_retry(
            requests.post, comment_url,
            auth=jira_auth(), headers=headers, json={"body": adf_body},
            label=f"Jira post comment[{comment_index}] (ADF/table) to {issue_key}"
        )
    else:
        final_body = build_comment_body_with_images(parts, image_url_map, meta_line, issue_key)
        comment_url = f"{clean_base(JIRA_URL)}/rest/api/2/issue/{issue_key}/comment"
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        r = api_call_with_retry(
            requests.post, comment_url,
            auth=jira_auth(), headers=headers, json={"body": final_body},
            label=f"Jira post comment[{comment_index}] to {issue_key}"
        )

    if r.status_code in (200, 201):
        log(f"   ✅ Comment[{comment_index}] posted ({img_upload_count} images OK, {img_fail_count} failed)")
        log_to_excel(wi_id, issue_key, f"Comment[{comment_index}]", "Success",
                     f"Text + {img_upload_count} images")
    else:
        log(f"   ❌ Comment[{comment_index}] failed: {r.status_code}")
        log_to_excel(wi_id, issue_key, f"Comment[{comment_index}]", "Failed",
                     f"HTTP {r.status_code}")


def _post_single_comment(issue_key: str, body: str, wi_id=None, comment_index: int = 0):
    comment_url = f"{clean_base(JIRA_URL)}/rest/api/2/issue/{issue_key}/comment"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    try:
        r = api_call_with_retry(
            requests.post, comment_url,
            auth=jira_auth(), headers=headers, json={"body": body},
            label=f"Jira post comment[{comment_index}] to {issue_key}"
        )
        if r.status_code not in (200, 201):
            log(f"   ❌ Comment[{comment_index}] post failed: {r.status_code} {r.text[:200]}")
            log_to_excel(wi_id, issue_key, f"Comment[{comment_index}]", "Failed",
                         f"HTTP {r.status_code}: {r.text[:80]}")
    except Exception as e:
        log(f"   ❌ Comment[{comment_index}] post exception: {e}")

# ============================================================
# END COMMENT HANDLING
# ============================================================

def migrate_all():
    ensure_dir(ATTACH_DIR)

    if os.path.exists(MAPPING_FILE):
        with open(MAPPING_FILE, "r") as f:
            mapping = json.load(f)
    else:
        mapping = {}

    wiql = (
        "SELECT [System.Id] FROM WorkItems WHERE [System.CreatedDate] >= '2026-04-01' "
        "AND [System.CreatedDate] <= '2026-04-15' AND [System.WorkItemType] = 'Epic'"
    )
    ids = ado_wiql_all_ids(wiql)
    if not ids:
        log("No work items found.")
        return

    log(f"📌 Found {len(ids)} work items.")

    SPECIFIC_ID = None

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

            # 2) Create ADO → Jira remote links
            try:
                create_links_from_ado(wi, issue_key)
                log_to_excel(wi_id, issue_key, "Create Links", "Success", "Links created from ADO relations")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Create Links", "Error", str(e)[:100])

            # 3) Update Steps field
            try:
                url = f"{JIRA_URL}rest/api/3/issue/{issue_key}"
                headers = {"Content-Type": "application/json"}
                if steps_payload and steps_payload.strip() != " ":
                    with open("output.txt", "a", encoding="utf-8") as f:
                        f.write(f"{steps_payload}\n")
                    with open("output1.txt", "a", encoding="utf-8") as f:
                        f.write(f"{url}\n{json.dumps(steps_payload, indent=2)}\n\n")
                    r = api_call_with_retry(
                        requests.put, url,
                        auth=jira_auth(), headers=headers, data=steps_payload,
                        label=f"Jira update steps {issue_key}"
                    )
                    if r.status_code in (200, 204):
                        log(f"✅ Updated Steps for {issue_key}")
                        log_to_excel(wi_id, issue_key, "Update Steps", "Success", "Steps updated successfully")
                    else:
                        log(f"⚠️ Failed to update steps for {issue_key}: {r.status_code} {r.text}")
                        log_to_excel(wi_id, issue_key, "Update Steps", "Failed", f"{r.status_code} {r.text[:100]}")
                else:
                    log_to_excel(wi_id, issue_key, "Update Steps", "Skipped", "No steps content in ADO")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Update Steps", "Error", str(e)[:100])

            # 4) Update Description field
            try:
                raw_desc = wi.get("fields", {}).get("System.Description", "")
                if raw_desc:
                    log_to_excel(wi_id, issue_key, "Description", "Processing", "Processing description with table support")
                    desc_adf = improved_process_description_to_adf(issue_key, raw_desc)
                    base = clean_base(JIRA_URL)
                    url = f"{base}/rest/api/3/issue/{issue_key}"
                    payload = {"fields": {"description": desc_adf}}
                    headers = {"Content-Type": "application/json"}
                    r = api_call_with_retry(
                        requests.put, url,
                        auth=jira_auth(), headers=headers, json=payload,
                        label=f"Jira update description {issue_key}"
                    )
                    if r.status_code in (200, 204):
                        log(f"✅ Updated description for {issue_key}")
                        log_to_excel(wi_id, issue_key, "Update Description", "Success", "Description updated successfully")
                    else:
                        log(f"⚠️ Failed to update description: {r.status_code} {r.text}")
                        log_to_excel(wi_id, issue_key, "Update Description", "Failed", f"{r.status_code} {r.text[:100]}")
                else:
                    log_to_excel(wi_id, issue_key, "Description", "Skipped", "No description in ADO")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Update Description", "Error", str(e)[:100])

            if not issue_key:
                continue

            # Save mapping
            mapping[wi_id_str] = issue_key
            with open(MAPPING_FILE, "w") as f:
                json.dump(mapping, f, indent=2)

            # 5) Transition status
            try:
                ado_state = wi.get("fields", {}).get("System.State", "New")
                jira_transition_issue(issue_key, ado_state)
                log_to_excel(wi_id, issue_key, "Transition", "Success", f"Transitioned to {STATE_MAP.get(ado_state, 'NA')}")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Transition", "Error", str(e)[:100])

            # 6) Attachments migration
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
                            local_path = ado_download_attachment(att_url, att_filename)
                            if local_path and os.path.exists(local_path):
                                upload_result = jira_upload_attachment(issue_key, local_path)
                                if upload_result and upload_result.get("id"):
                                    log(f"   ✅ Uploaded attachment: {att_filename}")
                                    log_to_excel(wi_id, issue_key, "Upload Attachment", "Success", f"Uploaded {att_filename}")
                                else:
                                    log(f"   ⚠️ Failed to upload: {att_filename}")
                                    log_to_excel(wi_id, issue_key, "Upload Attachment", "Failed", f"Upload failed for {att_filename}")
                                try:
                                    os.remove(local_path)
                                except Exception as e:
                                    log(f"   ⚠️ Could not delete local file {local_path}: {e}")
                            else:
                                log(f"   ⚠️ Download failed for: {att_filename}")
                                log_to_excel(wi_id, issue_key, "Download Attachment", "Failed", f"Download failed for {att_filename}")
                        except Exception as e:
                            log_to_excel(wi_id, issue_key, "Process Attachment", "Error", str(e)[:100])
                else:
                    log_to_excel(wi_id, issue_key, "Attachments", "Skipped", "No attachments in ADO")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Attachments", "Error", str(e)[:100])

            # 7) Comments — improved pipeline from Code 1
            try:
                comments = ado_get_comments(wi_id)
                if comments:
                    log_to_excel(wi_id, issue_key, "Comments", "Processing",
                                 f"Found {len(comments)} comments")
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

                        log(f"   💬 Processing comment {idx + 1}/{len(comments)} "
                            f"by {author} on {created_str}")

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
                            log_to_excel(wi_id, issue_key, f"Comment[{idx + 1}]",
                                         "Error", str(e)[:100])
                            fail_count += 1

                    log_to_excel(wi_id, issue_key, "Comments_Summary", "Complete",
                                 f"{ok_count} OK, {fail_count} failed of {len(comments)}")
                else:
                    log_to_excel(wi_id, issue_key, "Comments", "Skipped", "No comments in ADO")
            except Exception as e:
                log_to_excel(wi_id, issue_key, "Comments", "Error", str(e)[:100])

    log("🎉 Migration completed.")

    # Cleanup temp attachments
    try:
        for file in os.listdir("ado_attachments"):
            try:
                os.remove(os.path.join("ado_attachments", file))
            except Exception as e:
                print(f"Failed to delete {file}: {e}")
    except Exception as e:
        print(f"Failed to cleanup attachments directory: {e}")

    # Save migration log
    if migration_log:
        df = pd.DataFrame(list(migration_log.values()))
        df.to_excel("migration_log.xlsx", index=False)
        print("✅ Migration log saved to migration_log.xlsx")


if __name__ == "__main__":
    migrate_all()