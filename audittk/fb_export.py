"""Facebook / Meta Business Manager export via the Graph API.

There is no "Security Center API" - the Security Centre page in Business
Manager is a view over the business activity log, which IS available at
GET /{business-id}/activities with the business_management permission.
That endpoint is the whole evidential basis for the Facebook side.

Retention is the constraint here: Meta's business activity log is short
lived compared to Google's (on the order of 90 days), so this export is
the only durable copy of it.

Usage:
    FB_TOKEN=... python -m audittk.fb_export --business 1234567890 \
        --out out/facebook --days 90
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from .common import emit, log, utcnow_iso, write_json

GRAPH_VERSION = os.environ.get("FB_GRAPH_VERSION", "v23.0")
GRAPH = "https://graph.facebook.com/" + GRAPH_VERSION


class GraphError(Exception):
    def __init__(self, status, payload):
        super().__init__("HTTP %s: %s" % (status, payload))
        self.status = status
        self.payload = payload


def graph_get(path, token, params=None, attempts=5):
    """One Graph call, with backoff on Meta's rate limit codes (4, 17, 32, 613)."""
    query = dict(params or {})
    query["access_token"] = token
    url = "%s/%s?%s" % (GRAPH, path.lstrip("/"), urllib.parse.urlencode(query))
    delay = 2.0
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=120) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            try:
                code = json.loads(body).get("error", {}).get("code")
            except Exception:  # noqa: BLE001
                code = None
            if code in (4, 17, 32, 613) or exc.code in (429, 500, 502, 503):
                log("  rate limited (code %s); sleeping %.0fs" % (code, delay))
                time.sleep(delay)
                delay *= 2
                continue
            raise GraphError(exc.code, body)
        except urllib.error.URLError as exc:
            log("  network error (%s); retrying in %.0fs" % (exc, delay))
            time.sleep(delay)
            delay *= 2
    raise GraphError(429, "exhausted retries on %s" % path)


def graph_page(path, token, params=None, max_pages=500):
    """Follow paging.next until exhausted."""
    out = []
    query = dict(params or {})
    query["access_token"] = token
    url = "%s/%s?%s" % (GRAPH, path.lstrip("/"), urllib.parse.urlencode(query))
    pages = 0
    while url and pages < max_pages:
        delay = 2.0
        for attempt in range(5):
            try:
                with urllib.request.urlopen(url, timeout=120) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", "replace")
                try:
                    code = json.loads(body).get("error", {}).get("code")
                except Exception:  # noqa: BLE001
                    code = None
                if code in (4, 17, 32, 613) or exc.code in (429, 500, 502, 503):
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise GraphError(exc.code, body)
        else:
            raise GraphError(429, "exhausted retries paging %s" % path)
        out.extend(payload.get("data", []) or [])
        url = (payload.get("paging") or {}).get("next")
        pages += 1
    return out


def collect(out_dir, name, fn, errors, index):
    try:
        rows = fn()
    except GraphError as exc:
        log("  skipped %s (%s)" % (name, exc))
        errors.append({"source": name, "error": str(exc)[:600]})
        index[name] = {"records": None, "status": str(exc)[:200]}
        return []
    emit(out_dir, name, rows)
    index[name] = {"records": len(rows), "status": "ok"}
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description="Export Meta Business Manager audit data")
    ap.add_argument("--business", action="append", default=[],
                    help="business id; repeatable. Omit to discover from the token.")
    ap.add_argument("--out", default="out/facebook")
    ap.add_argument("--days", type=int, default=90,
                    help="activity log window; Meta retains roughly 90 days")
    ap.add_argument("--token", default=os.environ.get("FB_TOKEN"),
                    help="system user access token (or set FB_TOKEN)")
    args = ap.parse_args(argv)

    if not args.token:
        log("no token: pass --token or set FB_TOKEN")
        return 2

    token = args.token
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=args.days)
    errors = []
    index = {}

    # Prove what this token actually is before trusting anything it returns.
    # A token with the wrong scopes returns empty lists, not errors, and an
    # empty list reads exactly like "nothing to find".
    try:
        debug = graph_get("debug_token", token, {"input_token": token})
        write_json(args.out, "token_debug", debug)
        scopes = (debug.get("data") or {}).get("scopes", [])
        log("token scopes: %s" % ", ".join(scopes))
        missing = [s for s in ("business_management",) if s not in scopes]
        if missing:
            log("WARNING: token is missing %s - the activity log will come back empty"
                % ", ".join(missing))
            errors.append({"source": "token_debug",
                           "error": "missing scopes: %s" % ", ".join(missing)})
    except GraphError as exc:
        errors.append({"source": "debug_token", "error": str(exc)[:600]})

    businesses = args.business
    if not businesses:
        try:
            found = graph_page("me/businesses", token, {"fields": "id,name,verification_status"})
            emit(args.out, "businesses", found)
            businesses = [b["id"] for b in found]
        except GraphError as exc:
            errors.append({"source": "me/businesses", "error": str(exc)[:600]})
    if not businesses:
        log("no business id resolved; pass --business")
        write_json(args.out, "_collection_metadata",
                   {"collected_at": utcnow_iso(), "errors": errors})
        return 1

    for biz in businesses:
        log("business %s" % biz)
        d = os.path.join(args.out, "business_%s" % biz)

        # The activity log. Meta caps the window per call, so we walk it in
        # 7 day slices - one long since/until often silently returns less.
        activities = []
        cursor = start
        while cursor < end:
            chunk_end = min(cursor + timedelta(days=7), end)
            try:
                rows = graph_page("%s/activities" % biz, token, {
                    "since": int(cursor.timestamp()),
                    "until": int(chunk_end.timestamp()),
                    "limit": 200,
                    "fields": "actor_id,actor_name,event_type,event_time,extra_data,"
                              "object_id,object_name,object_type,title",
                })
                activities.extend(rows)
            except GraphError as exc:
                errors.append({"source": "%s/activities" % biz,
                               "window": "%s..%s" % (cursor.date(), chunk_end.date()),
                               "error": str(exc)[:600]})
            cursor = chunk_end
        emit(d, "activities", activities)
        index["business_%s/activities" % biz] = {"records": len(activities)}

        collect(d, "business_users", lambda: graph_page(
            "%s/business_users" % biz, token,
            {"fields": "id,name,email,role,title,pending_email", "limit": 100}), errors, index)
        collect(d, "system_users", lambda: graph_page(
            "%s/system_users" % biz, token,
            {"fields": "id,name,role,created_by", "limit": 100}), errors, index)
        collect(d, "pending_users", lambda: graph_page(
            "%s/pending_users" % biz, token,
            {"fields": "id,email,role,expiration_time,invite_link", "limit": 100}), errors, index)
        collect(d, "admin_system_user_assets", lambda: graph_page(
            "%s/owned_businesses" % biz, token, {"fields": "id,name", "limit": 100}),
            errors, index)

        # Assets. Ownership changes are the usual way value walks out of a
        # business quietly - an ad account "shared" to an outside business
        # keeps working long after the person loses their login.
        for edge, fields in [
            ("owned_ad_accounts", "id,name,account_status,business,created_time,"
                                  "funding_source_details,owner,timezone_name"),
            ("client_ad_accounts", "id,name,account_status,business,owner"),
            ("owned_pages", "id,name,verification_status"),
            ("client_pages", "id,name"),
            ("owned_apps", "id,name"),
            ("owned_pixels", "id,name,owner_business,last_fired_time"),
            ("owned_instagram_accounts", "id,username"),
            ("agencies", "id,name,verification_status"),
            ("clients", "id,name"),
            ("initiated_audience_sharing_requests", "id,request_status,receiving_business"),
            ("received_audience_sharing_requests", "id,request_status,requesting_business"),
        ]:
            collect(d, edge, (lambda e=edge, f=fields: graph_page(
                "%s/%s" % (biz, e), token, {"fields": f, "limit": 100})), errors, index)

        # Per-asset assignments: which person holds which permission on which
        # ad account. Business-level role alone does not tell you this.
        assignments = []
        for asset_edge in ("owned_ad_accounts", "owned_pages"):
            path = os.path.join(d, asset_edge + ".json")
            if not os.path.exists(path):
                continue
            with open(path, encoding="utf-8") as fh:
                assets = json.load(fh)
            for asset in assets:
                try:
                    users = graph_page("%s/assigned_users" % asset["id"], token,
                                       {"business": biz, "fields": "id,name,tasks", "limit": 100})
                except GraphError as exc:
                    errors.append({"source": "%s/assigned_users" % asset["id"],
                                   "error": str(exc)[:400]})
                    continue
                for user in users:
                    assignments.append({
                        "asset_type": asset_edge,
                        "asset_id": asset["id"],
                        "asset_name": asset.get("name"),
                        "user_id": user.get("id"),
                        "user_name": user.get("name"),
                        "tasks": user.get("tasks"),
                    })
        emit(d, "asset_assignments", assignments)
        index["business_%s/asset_assignments" % biz] = {"records": len(assignments)}

    write_json(args.out, "_collection_metadata", {
        "collected_at": utcnow_iso(),
        "graph_version": GRAPH_VERSION,
        "window_start": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_end": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "businesses": businesses,
        "retention_caveat": "Meta's business activity log is short retention (roughly 90 "
                            "days). Events older than that are not missing from this export "
                            "because nothing happened - they are simply no longer available.",
        "collections": index,
        "errors": errors,
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
