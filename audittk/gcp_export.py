"""GCP export: Cloud Logging audit entries + current IAM policy.

Two things worth knowing before reading the output:

1. Admin Activity audit logs go to the _Required bucket. They are retained
   400 days, cannot be disabled, and cannot be deleted - not even by an
   owner. That makes them the strongest evidence available here.
2. Data Access audit logs (who READ or EXPORTED data) are off by default.
   If they were never enabled, the absence of read events is not evidence
   that nothing was read. This script reports which services have them
   enabled so that distinction lands in the report rather than getting lost.

Usage:
    python -m audittk.gcp_export --key sa.json --out out/gcp --days 180 \
        [--org 123456789012] [--project my-project ...]
"""

import argparse
import sys
from datetime import datetime, timedelta, timezone

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from .common import emit, log, retry, utcnow_iso, write_json

SCOPES = ["https://www.googleapis.com/auth/cloud-platform.read-only"]

# _Required holds Admin Activity and System Event logs and is immutable.
# _Default holds everything else, including Data Access if it was turned on.
BUCKETS = ["_Required", "_Default"]


def _reason(exc):
    try:
        return exc._get_reason().strip()
    except Exception:  # noqa: BLE001
        return str(exc)


def _is_retryable(exc):
    if not isinstance(exc, HttpError):
        return False
    return exc.resp.status in (429, 500, 502, 503)


def credentials(key_file):
    return service_account.Credentials.from_service_account_file(key_file, scopes=SCOPES)


def discover_projects(crm, out_dir, errors):
    try:
        projects = []
        token = None
        while True:
            body = {"query": "state:ACTIVE"}
            if token:
                body["pageToken"] = token
            resp = retry(lambda: crm.projects().search(**body).execute(), on_error=_is_retryable)
            projects.extend(resp.get("projects", []) or [])
            token = resp.get("nextPageToken")
            if not token:
                break
        emit(out_dir, "projects", projects)
        return [p["projectId"] for p in projects]
    except HttpError as exc:
        detail = "HTTP %s: %s" % (exc.resp.status, _reason(exc))
        log("project discovery failed (%s) - pass --project explicitly" % detail)
        errors.append({"source": "cloudresourcemanager.projects.search", "error": detail})
        return []


def export_iam_policies(crm, projects, out_dir, errors):
    """Who can do what, right now. The counterpart to the activity log."""
    policies = []
    for project_id in projects:
        try:
            policy = retry(
                lambda: crm.projects().getIamPolicy(
                    resource="projects/%s" % project_id, body={}).execute(),
                on_error=_is_retryable,
            )
        except HttpError as exc:
            errors.append({"source": "getIamPolicy", "project": project_id,
                           "error": "HTTP %s: %s" % (exc.resp.status, _reason(exc))})
            continue
        # auditConfigs is where Data Access logging is switched on or off.
        policies.append({
            "project": project_id,
            "bindings": policy.get("bindings", []),
            "auditConfigs": policy.get("auditConfigs", []),
            "etag": policy.get("etag"),
        })
    emit(out_dir, "iam_policies", policies)
    return policies


def export_log_entries(logging_api, resource_names, out_dir, name, log_filter, errors,
                       page_limit=200):
    """Page entries:list. page_limit caps a runaway pull on a noisy project;
    if we hit it we say so rather than silently truncating the evidence."""
    entries = []
    token = None
    pages = 0
    truncated = False
    while True:
        body = {
            "resourceNames": resource_names,
            "filter": log_filter,
            "orderBy": "timestamp desc",
            "pageSize": 1000,
        }
        if token:
            body["pageToken"] = token
        try:
            resp = retry(lambda: logging_api.entries().list(body=body).execute(),
                         on_error=_is_retryable)
        except HttpError as exc:
            detail = "HTTP %s: %s" % (exc.resp.status, _reason(exc))
            log("  %s failed (%s)" % (name, detail))
            errors.append({"source": "logging.entries.list", "collection": name,
                           "error": detail, "filter": log_filter})
            break
        entries.extend(resp.get("entries", []) or [])
        token = resp.get("nextPageToken")
        pages += 1
        if not token:
            break
        if pages >= page_limit:
            truncated = True
            log("  %s hit the %d page cap - export is TRUNCATED" % (name, page_limit))
            errors.append({"source": "logging.entries.list", "collection": name,
                           "error": "truncated at %d pages (~%d entries); narrow --days or "
                                    "split by project" % (page_limit, len(entries))})
            break
    emit(out_dir, name, entries)
    return {"records": len(entries), "truncated": truncated}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Export GCP Cloud Logging audit entries and IAM state")
    ap.add_argument("--key", required=True)
    ap.add_argument("--out", default="out/gcp")
    ap.add_argument("--days", type=int, default=180)
    ap.add_argument("--project", action="append", default=[],
                    help="project id; repeatable. Omit to auto-discover.")
    ap.add_argument("--org", help="organization id, to also pull org-level audit logs")
    args = ap.parse_args(argv)

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=args.days)
    since = start.strftime("%Y-%m-%dT%H:%M:%SZ")

    creds = credentials(args.key)
    crm = build("cloudresourcemanager", "v3", credentials=creds, cache_discovery=False)
    logging_api = build("logging", "v2", credentials=creds, cache_discovery=False)

    errors = []
    projects = args.project or discover_projects(crm, args.out, errors)
    if not projects and not args.org:
        log("no projects resolved and no --org given; nothing to pull")
        write_json(args.out, "_collection_metadata", {
            "collected_at": utcnow_iso(), "errors": errors,
            "note": "no projects resolved - grant the service account Viewer + "
                    "Private Logs Viewer, or pass --project",
        })
        return 1

    resource_names = ["projects/%s" % p for p in projects]
    if args.org:
        resource_names.append("organizations/%s" % args.org)
    log("resources: %s" % ", ".join(resource_names))

    iam = export_iam_policies(crm, projects, args.out, errors)

    time_clause = 'timestamp >= "%s"' % since
    collections = {}

    # Admin Activity: every permission change, every resource created or
    # destroyed. This is the immutable one.
    collections["audit_admin_activity"] = export_log_entries(
        logging_api, resource_names, args.out, "audit_admin_activity",
        'logName:"cloudaudit.googleapis.com%2Factivity" AND ' + time_clause, errors)

    # System Event: actions Google took, not a person.
    collections["audit_system_event"] = export_log_entries(
        logging_api, resource_names, args.out, "audit_system_event",
        'logName:"cloudaudit.googleapis.com%2Fsystem_event" AND ' + time_clause, errors)

    # Data Access: only present if it was explicitly enabled.
    collections["audit_data_access"] = export_log_entries(
        logging_api, resource_names, args.out, "audit_data_access",
        'logName:"cloudaudit.googleapis.com%2Fdata_access" AND ' + time_clause, errors)

    # Policy Denied: an identity that tried something it was not allowed to.
    collections["audit_policy_denied"] = export_log_entries(
        logging_api, resource_names, args.out, "audit_policy_denied",
        'logName:"cloudaudit.googleapis.com%2Fpolicy" AND ' + time_clause, errors)

    # IAM and key changes, pulled separately so they are easy to read on
    # their own rather than buried in the full activity dump.
    collections["iam_changes"] = export_log_entries(
        logging_api, resource_names, args.out, "iam_changes",
        # Cloud Logging records these under their gRPC names, so match those
        # as well as the REST spellings - filtering on only one of the two
        # returns an empty result that looks like a clean history.
        'protoPayload.methodName:("SetIamPolicy" OR "CreateServiceAccount" OR '
        '"DeleteServiceAccount" OR "CreateServiceAccountKey" OR '
        '"DeleteServiceAccountKey" OR "serviceAccounts.create" OR '
        '"serviceAccounts.delete" OR "serviceAccounts.keys.create" OR '
        '"serviceAccounts.keys.delete") AND ' + time_clause, errors)

    data_access_enabled = [
        {"project": p["project"], "auditConfigs": p["auditConfigs"]}
        for p in iam if p.get("auditConfigs")
    ]

    write_json(args.out, "_collection_metadata", {
        "collected_at": utcnow_iso(),
        "window_start": since,
        "window_end": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "resource_names": resource_names,
        "buckets_note": "Admin Activity lives in the immutable _Required bucket "
                        "(400 day retention). _Default defaults to 30 days.",
        "data_access_logging": {
            "projects_with_audit_configs": data_access_enabled,
            "caveat": "Where no auditConfig is present, Data Access logging was OFF. "
                      "An empty audit_data_access export therefore does NOT mean no "
                      "data was read or exported.",
        },
        "collections": collections,
        "errors": errors,
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
