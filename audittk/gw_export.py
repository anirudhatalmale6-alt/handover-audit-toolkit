"""Google Workspace export: Admin SDK Reports API + Directory API.

Read-only. Every scope requested below ends in .readonly except
admin.directory.user.security, which is the only scope Google offers for
listing a user's issued OAuth tokens and app passwords - there is no
readonly variant of it. It still only reads here; nothing in this file
calls a delete or update method.

Usage:
    python -m audittk.gw_export --key sa.json --admin you@domain.com \
        --out out/google --days 180
"""

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from .common import emit, log, retry, utcnow_iso, write_json

SCOPES = [
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.reports.usage.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
    "https://www.googleapis.com/auth/admin.directory.domain.readonly",
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
    "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
    "https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.security",
]

# Reports API application names. Not every tenant has every one of these -
# a tenant without Chrome Enterprise or Vault will 400 on those, which we
# record rather than swallow, so the final report can say "not available"
# instead of implying the log was empty.
APPLICATIONS = [
    "admin",            # every change made in the Admin console
    "login",            # successful and failed sign-ins, suspicious login
    "drive",            # file create/edit/delete/download/share
    "token",            # OAuth tokens granted to third-party apps
    "groups",
    "groups_enterprise",
    "saml",
    "user_accounts",    # 2SV enrolment changes, password changes
    "mobile",
    "calendar",
    "gcp",
    "chat",
    "meet",
    "rules",
    "access_transparency",
    "chrome",
    "context_aware_access",
    "keep",
    "data_studio",
    "vault",
]


def credentials(key_file, admin_email):
    creds = service_account.Credentials.from_service_account_file(key_file, scopes=SCOPES)
    # Domain-wide delegation: the service account acts as the super admin,
    # which is what gives it visibility of the whole tenant rather than of
    # one mailbox.
    return creds.with_subject(admin_email)


def _reason(exc):
    """HttpError's reason lives on a private method; fall back to str()."""
    try:
        return exc._get_reason().strip()
    except Exception:  # noqa: BLE001 - diagnostics only
        return str(exc)


def _is_retryable(exc):
    """429/500/503 are transient. A 403 is only transient when it is a quota
    rejection - a 403 for a missing scope will never succeed on retry, and
    retrying it just hides the real problem for 60 seconds."""
    if not isinstance(exc, HttpError):
        return False
    status = exc.resp.status
    if status in (429, 500, 502, 503):
        return True
    if status == 403:
        return any(word in str(exc).lower() for word in ("quota", "rate limit", "ratelimit"))
    return False


def page_all(request_fn, list_key, **kwargs):
    """Page a Google API list method until exhausted."""
    items = []
    token = None
    while True:
        params = dict(kwargs)
        if token:
            params["pageToken"] = token
        resp = retry(lambda: request_fn(**params).execute(), on_error=_is_retryable)
        items.extend(resp.get(list_key, []) or [])
        token = resp.get("nextPageToken")
        if not token:
            return items


def export_activities(reports, out_dir, start_time, end_time, errors):
    """Pull every audit application. This is the bulk of the evidence."""
    index = {}
    for app in APPLICATIONS:
        log("reports: %s" % app)
        try:
            rows = page_all(
                reports.activities().list,
                "items",
                userKey="all",
                applicationName=app,
                startTime=start_time,
                endTime=end_time,
                maxResults=1000,
            )
        except HttpError as exc:
            status = exc.resp.status
            detail = "HTTP %s: %s" % (status, _reason(exc))
            log("  skipped %s (%s)" % (app, detail))
            errors.append({"source": "reports.activities", "application": app, "error": detail})
            index[app] = {"records": None, "status": detail}
            continue
        emit(out_dir, "activity_%s" % app, rows)
        index[app] = {"records": len(rows), "status": "ok"}
    return index


def export_directory(directory, out_dir, customer, errors):
    """Current state: who exists, who is an admin, what is connected."""
    state = {}

    def grab(name, fn):
        try:
            rows = fn()
        except HttpError as exc:
            detail = "HTTP %s: %s" % (exc.resp.status, _reason(exc))
            log("  skipped %s (%s)" % (name, detail))
            errors.append({"source": "directory." + name, "error": detail})
            state[name] = None
            return []
        emit(out_dir, name, rows)
        state[name] = len(rows)
        return rows

    users = grab("users", lambda: page_all(
        directory.users().list, "users",
        customer=customer, maxResults=500, projection="full", showDeleted="false",
    ))
    # Deleted users are the whole point of this job: Google keeps them
    # restorable for 20 days and listed here for that window only.
    grab("users_deleted", lambda: page_all(
        directory.users().list, "users",
        customer=customer, maxResults=500, showDeleted="true",
    ))
    grab("domains", lambda: directory.domains().list(customer=customer).execute().get("domains", []))
    grab("orgunits", lambda: directory.orgunits().list(
        customerId=customer, type="all").execute().get("organizationUnits", []))
    grab("roles", lambda: page_all(directory.roles().list, "items", customer=customer, maxResults=100))
    grab("role_assignments", lambda: page_all(
        directory.roleAssignments().list, "items", customer=customer, maxResults=200))
    grab("groups", lambda: page_all(
        directory.groups().list, "groups", customer=customer, maxResults=200))
    grab("mobile_devices", lambda: page_all(
        directory.mobiledevices().list, "mobiledevices", customerId=customer, maxResults=100))

    # Third-party OAuth tokens, per user. There is no tenant-wide list
    # method for this, so it is one call per user - the slow part of the run,
    # and the part most likely to surface an integration nobody remembers
    # authorising.
    tokens = []
    for user in users:
        email = user.get("primaryEmail")
        try:
            resp = retry(
                lambda: directory.tokens().list(userKey=email).execute(),
                on_error=_is_retryable,
            )
        except HttpError as exc:
            errors.append({"source": "directory.tokens", "user": email,
                           "error": "HTTP %s: %s" % (exc.resp.status, _reason(exc))})
            continue
        for tok in resp.get("items", []) or []:
            tok["_user"] = email
            tokens.append(tok)
    emit(out_dir, "oauth_tokens", tokens)
    state["oauth_tokens"] = len(tokens)

    asps = []
    for user in users:
        email = user.get("primaryEmail")
        try:
            resp = retry(lambda: directory.asps().list(userKey=email).execute(),
                         on_error=_is_retryable)
        except HttpError:
            continue
        for asp in resp.get("items", []) or []:
            asp["_user"] = email
            asps.append(asp)
    emit(out_dir, "app_passwords", asps)
    state["app_passwords"] = len(asps)

    return state


def main(argv=None):
    ap = argparse.ArgumentParser(description="Export Google Workspace audit logs and current state")
    ap.add_argument("--key", required=True, help="service account JSON key file")
    ap.add_argument("--admin", required=True, help="super admin email to impersonate")
    ap.add_argument("--out", default="out/google")
    ap.add_argument("--days", type=int, default=180,
                    help="how far back to pull; Google retains most audit logs for 180 days")
    ap.add_argument("--customer", default="my_customer")
    args = ap.parse_args(argv)

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=args.days)
    start_time = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_time = end.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    creds = credentials(args.key, args.admin)
    reports = build("admin", "reports_v1", credentials=creds, cache_discovery=False)
    directory = build("admin", "directory_v1", credentials=creds, cache_discovery=False)

    errors = []
    log("window %s .. %s" % (start_time, end_time))
    activity_index = export_activities(reports, args.out, start_time, end_time, errors)
    directory_index = export_directory(directory, args.out, args.customer, errors)

    write_json(args.out, "_collection_metadata", {
        "collected_at": utcnow_iso(),
        "collected_by_scopes": SCOPES,
        "impersonated_admin": args.admin,
        "customer": args.customer,
        "window_start": start_time,
        "window_end": end_time,
        "activity_applications": activity_index,
        "directory_collections": directory_index,
        "errors": errors,
    })
    if errors:
        log("%d collection errors recorded in _collection_metadata.json" % len(errors))
    return 0


if __name__ == "__main__":
    sys.exit(main())
