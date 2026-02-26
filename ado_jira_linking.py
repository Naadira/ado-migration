import requests
import json
import time
from requests.auth import HTTPBasicAuth
from openpyxl import Workbook
import os

# =============================================
# CONFIGURATION
# =============================================

# ADO
ADO_ORG = "HESource"
ADO_PROJECT = "Source"
ADO_PAT = ""

# Jira
JIRA_BASE_URL = "https://healthedge-sandbox-ado-testing.atlassian.net/"
JIRA_EMAIL = "naadira.sahar@healthedge.com"
JIRA_API_TOKEN = ""
MAPPING_FILE = "ado_jira_mapping.json"

MAX_RETRIES = 5
BASE_WAIT = 2


session = requests.Session()
session.auth = HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN)
session.headers.update({"Content-Type": "application/json"})
# =============================================
# LOAD FULL MAPPING (20K+)
# =============================================

with open(MAPPING_FILE, "r") as f:
    ado_to_jira = json.load(f)

processed_pairs = set()

# =============================================
# RESUME SUPPORT
# =============================================

CHECKPOINT_FILE = "progress_checkpoint.txt"

start_processing = False
last_processed_id = None

if os.path.exists(CHECKPOINT_FILE):
    with open(CHECKPOINT_FILE, "r") as f:
        last_processed_id = f.read().strip()
        print(f"🔁 Resuming from last processed ADO ID: {last_processed_id}")
else:
    print("🚀 Starting fresh run...")
    start_processing = True

# =============================================
# SUMMARY COUNTERS
# =============================================

stats = {
    "CREATED": 0,
    "ALREADY_LINKED": 0,
    "SKIPPED_NOT_IN_MAPPING": 0,
    "NO_RELATIONS": 0,
    "FAILED": 0,
    "ADO_FETCH_FAILED": 0
}

# =============================================
# EXCEL REPORT
# =============================================

wb = Workbook()
ws = wb.active
ws.append([
    "Source ADO",
    "Source Jira",
    "Target ADO",
    "Target Jira",
    "Status",
    "Message"
])

# =============================================
# RETRY WRAPPER (JIRA)
# =============================================

def jira_post_with_retry(url, payload):
    wait = BASE_WAIT

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = session.post(
            url,
            data=json.dumps(payload),
            timeout=30
            )

            # Handle rate limit
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                if retry_after:
                    wait = int(retry_after)

                print(f"⚠ 429 hit. Waiting {wait}s")
                time.sleep(wait)
                wait *= 2
                continue

            return response

        except requests.exceptions.ConnectionError as e:
            print(f"⚠ Connection dropped. Retrying in {wait}s (Attempt {attempt}/{MAX_RETRIES})")
            time.sleep(wait)
            wait *= 2
            continue

        except requests.exceptions.Timeout:
            print(f"⚠ Timeout. Retrying in {wait}s (Attempt {attempt}/{MAX_RETRIES})")
            time.sleep(wait)
            wait *= 2
            continue

    print("❌ Max retries reached.")
    raise Exception("Jira POST failed after retries")
# =============================================
# CHECK IF JIRA LINK EXISTS
# =============================================

def jira_link_exists(source_key, target_key):
    url = f"{JIRA_BASE_URL}/rest/api/3/issue/{source_key}?fields=issuelinks"

    response = requests.get(
        url,
        auth=HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN)
    )

    if response.status_code != 200:
        return False

    links = response.json().get("fields", {}).get("issuelinks", [])

    for link in links:
        inward = link.get("inwardIssue")
        outward = link.get("outwardIssue")

        if inward and inward.get("key") == target_key:
            return True

        if outward and outward.get("key") == target_key:
            return True

    return False

# =============================================
# FETCH ADO RELATIONS
# =============================================

def get_ado_relations(work_item_id):
    url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/workitems/{work_item_id}?$expand=relations&api-version=7.0"
    response = requests.get(url, auth=("", ADO_PAT))
    response.raise_for_status()
    return response.json().get("relations", [])

# =============================================
# MAIN PROCESS (PROCESS ALL MAPPED ITEMS)
# =============================================

for ado_id, jira_source in ado_to_jira.items():

    # Resume logic
    if not start_processing:
        if ado_id == last_processed_id:
            start_processing = True
        continue

    print(f"\nProcessing ADO {ado_id} → Jira {jira_source}")

    try:
        relations = get_ado_relations(ado_id)
    except Exception as e:
        stats["ADO_FETCH_FAILED"] += 1
        ws.append([ado_id, jira_source, "", "", "ADO_FETCH_FAILED", str(e)])
        
        # Save checkpoint even if failed
        with open(CHECKPOINT_FILE, "w") as f:
            f.write(ado_id)
        continue

    if not relations:
        stats["NO_RELATIONS"] += 1
        ws.append([ado_id, jira_source, "", "", "NO_RELATIONS", ""])
        
        with open(CHECKPOINT_FILE, "w") as f:
            f.write(ado_id)
        continue

    for rel in relations:

        url = rel.get("url")
        if not url:
            continue

        linked_ado_id = url.split("/")[-1]

        if linked_ado_id not in ado_to_jira:
            stats["SKIPPED_NOT_IN_MAPPING"] += 1
            ws.append([
                ado_id,
                jira_source,
                linked_ado_id,
                "",
                "SKIPPED_NOT_IN_MAPPING",
                ""
            ])
            continue

        jira_target = ado_to_jira[linked_ado_id]

        if jira_source == jira_target:
            continue

        pair = tuple(sorted([jira_source, jira_target]))
        if pair in processed_pairs:
            continue

        link_url = f"{JIRA_BASE_URL}/rest/api/3/issueLink"

        payload = {
            "type": {"name": "Relates"},
            "inwardIssue": {"key": jira_source},
            "outwardIssue": {"key": jira_target},
        }

        if jira_link_exists(jira_source, jira_target):
            print(f"ℹ Already linked {jira_source} ↔ {jira_target}")
            stats["ALREADY_LINKED"] += 1
            ws.append([
                ado_id,
                jira_source,
                linked_ado_id,
                jira_target,
                "ALREADY_LINKED",
                ""
            ])
        else:
            response = jira_post_with_retry(link_url, payload)

            if response.status_code == 201:
                print(f"✅ Linked {jira_source} ↔ {jira_target}")
                stats["CREATED"] += 1
                ws.append([
                    ado_id,
                    jira_source,
                    linked_ado_id,
                    jira_target,
                    "CREATED",
                    ""
                ])
            else:
                print(f"❌ Failed {jira_source} ↔ {jira_target}")
                stats["FAILED"] += 1
                ws.append([
                    ado_id,
                    jira_source,
                    linked_ado_id,
                    jira_target,
                    "FAILED",
                    response.text
                ])

        processed_pairs.add(pair)
        time.sleep(0.02)

    # Save checkpoint after finishing this ADO item
    with open(CHECKPOINT_FILE, "w") as f:
        f.write(ado_id)

# =============================================
# SAVE REPORT
# =============================================

wb.save("jira_full_link_report.xlsx")

# =============================================
# PRINT SUMMARY
# =============================================

print("\n================ SUMMARY ================")
print(f"Total ADO Items Processed : {len(ado_to_jira)}")
print(f"Links Created             : {stats['CREATED']}")
print(f"Already Linked            : {stats['ALREADY_LINKED']}")
print(f"Skipped (Not in Mapping)  : {stats['SKIPPED_NOT_IN_MAPPING']}")
print(f"No Relations              : {stats['NO_RELATIONS']}")
print(f"ADO Fetch Failed          : {stats['ADO_FETCH_FAILED']}")
print(f"Failed (Jira Errors)      : {stats['FAILED']}")
print("=========================================\n")

print("✅ All work items processed.")