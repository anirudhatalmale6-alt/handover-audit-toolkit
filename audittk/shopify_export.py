"""Shopify export via the Admin API.

Read this before trusting the output, because Shopify's audit story is much
weaker than Google's and the gaps matter:

* The **Event API** retains 1 year, which is longer than anything else in this
  audit. But it only covers eight resource types - Article, Blog, Comment,
  CustomCollection, Order, Page, PriceRule, Product. Settings changes, app
  installs, payout and bank detail changes, and staff changes are NOT in it.
* The **store activity log** (Settings > General > Store activity log) is the
  only place most settings changes appear. It caps at **250 entries**, cannot
  be exported, and is not exposed by any API. It has to be screenshotted by
  hand, and it rolls off as the store stays busy. That is a deadline.
* **Staff login history** is the five most recent sessions per staff member,
  on that staff member's page. Remove the staff member and the page goes with
  them - which is why a former owner's activity "disappears" after a handover.
* The **user management activity log** (Settings > Users > Security) does
  record user and role create/edit/delete, but it is an organization-level
  feature and not available on every plan.

So: this script gets the 1 year of resource history and, more importantly,
the things a departing admin can leave behind - webhooks, script tags and
installed apps. Those are Shopify's equivalent of a leftover OAuth token:
they keep working after every password in the business has been changed.

Usage:
    SHOPIFY_TOKEN=shpat_... python -m audittk.shopify_export \
        --shop your-store.myshopify.com --out out/shopify --days 365
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from .common import emit, log, utcnow_iso, write_json

# Only these eight resource types appear in the Event API at all.
EVENT_RESOURCES = ["Article", "Blog", "Comment", "CustomCollection",
                   "Order", "Page", "PriceRule", "Product"]


class ShopifyError(Exception):
    def __init__(self, status, body):
        super().__init__("HTTP %s: %s" % (status, body[:400]))
        self.status = status
        self.body = body


def request(shop, token, path, version, params=None, absolute=None):
    """One Admin API call. Honours Shopify's Retry-After on 429."""
    if absolute:
        url = absolute
    else:
        url = "https://%s/admin/api/%s/%s" % (shop, version, path.lstrip("/"))
        if params:
            url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={
        "X-Shopify-Access-Token": token,
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    delay = 2.0
    for _attempt in range(6):
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body), resp.headers
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            if exc.code == 429:
                wait = float(exc.headers.get("Retry-After", delay))
                log("  throttled; sleeping %.1fs" % wait)
                time.sleep(wait)
                continue
            if exc.code in (500, 502, 503, 504):
                time.sleep(delay)
                delay *= 2
                continue
            raise ShopifyError(exc.code, body)
        except urllib.error.URLError as exc:
            log("  network error (%s); retrying in %.0fs" % (exc, delay))
            time.sleep(delay)
            delay *= 2
    raise ShopifyError(429, "exhausted retries on %s" % (absolute or path))


def next_link(headers):
    """Shopify pages via a Link header, not a body cursor."""
    link = headers.get("Link") or headers.get("link")
    if not link:
        return None
    for part in link.split(","):
        m = re.search(r'<([^>]+)>;\s*rel="next"', part.strip())
        if m:
            return m.group(1)
    return None


def page_all(shop, token, path, version, key, params=None, max_pages=400):
    out = []
    payload, headers = request(shop, token, path, version, params)
    out.extend(payload.get(key, []) or [])
    pages = 1
    url = next_link(headers)
    while url and pages < max_pages:
        payload, headers = request(shop, token, None, version, absolute=url)
        out.extend(payload.get(key, []) or [])
        url = next_link(headers)
        pages += 1
    if url:
        log("  %s hit the %d page cap - TRUNCATED" % (path, max_pages))
    return out


def resolve_version(shop, token, requested):
    """Ask the shop which API versions it supports rather than hardcoding one
    that may have been retired. Shopify keeps each version for about a year."""
    if requested:
        return requested, None
    try:
        payload, _ = request(shop, token, "api_versions.json", "unstable")
        versions = [v["handle"] for v in payload.get("api_versions", [])
                    if v.get("supported") and re.match(r"^\d{4}-\d{2}$", v.get("handle", ""))]
        if versions:
            chosen = sorted(versions)[-1]
            log("using API version %s (latest supported by this shop)" % chosen)
            return chosen, versions
    except ShopifyError as exc:
        log("version discovery failed (%s); falling back to 2025-01" % exc)
    return "2025-01", None


def collect(out_dir, name, fn, errors, index):
    try:
        rows = fn()
    except ShopifyError as exc:
        log("  skipped %s (%s)" % (name, exc))
        errors.append({"source": name, "error": str(exc)[:600]})
        index[name] = {"records": None, "status": str(exc)[:200]}
        return []
    emit(out_dir, name, rows)
    index[name] = {"records": len(rows), "status": "ok"}
    return rows


def graphql(shop, token, version, query):
    url = "https://%s/admin/api/%s/graphql.json" % (shop, version)
    req = urllib.request.Request(
        url, data=json.dumps({"query": query}).encode("utf-8"),
        headers={"X-Shopify-Access-Token": token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise ShopifyError(exc.code, exc.read().decode("utf-8", "replace"))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Export Shopify audit data")
    ap.add_argument("--shop", required=True, help="your-store.myshopify.com")
    ap.add_argument("--token", default=os.environ.get("SHOPIFY_TOKEN"),
                    help="custom app Admin API token (shpat_...), or set SHOPIFY_TOKEN")
    ap.add_argument("--out", default="out/shopify")
    ap.add_argument("--days", type=int, default=365,
                    help="Event API retains 1 year, so 365 is the useful maximum")
    ap.add_argument("--api-version", default=os.environ.get("SHOPIFY_API_VERSION"))
    args = ap.parse_args(argv)

    if not args.token:
        log("no token: pass --token or set SHOPIFY_TOKEN")
        return 2

    shop = args.shop.replace("https://", "").replace("http://", "").strip("/")
    token = args.token
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=args.days)
    errors, index = [], {}

    version, supported = resolve_version(shop, token, args.api_version)

    try:
        shop_info, _ = request(shop, token, "shop.json", version)
        write_json(args.out, "shop", shop_info.get("shop", {}))
        plan = (shop_info.get("shop") or {}).get("plan_name")
        log("shop: %s (plan: %s)" % (shop, plan))
    except ShopifyError as exc:
        log("cannot read shop.json (%s) - check the token and its scopes" % exc)
        write_json(args.out, "_collection_metadata",
                   {"collected_at": utcnow_iso(),
                    "error": "shop.json failed: %s" % str(exc)[:400]})
        return 1

    # The 1 year resource history. This is the strongest Shopify evidence
    # available and the only part that is genuinely exportable.
    collect(args.out, "events", lambda: page_all(
        shop, token, "events.json", version, "events",
        {"limit": 250, "created_at_min": start.strftime("%Y-%m-%dT%H:%M:%SZ")}),
        errors, index)

    # Deletions specifically, per resource type - the "she deleted something"
    # question, answered directly rather than by scrolling the full log.
    deletions = []
    for resource in EVENT_RESOURCES:
        try:
            rows = page_all(shop, token, "events.json", version, "events", {
                "limit": 250, "filter": resource, "verb": "destroy",
                "created_at_min": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
        except ShopifyError as exc:
            errors.append({"source": "events.destroy.%s" % resource, "error": str(exc)[:400]})
            continue
        for row in rows:
            row["_resource"] = resource
        deletions.extend(rows)
    emit(args.out, "events_deletions", deletions)
    index["events_deletions"] = {"records": len(deletions), "status": "ok"}

    # Leftover access. These are the Shopify equivalent of a stale OAuth token:
    # they survive every password change in the business.
    collect(args.out, "webhooks", lambda: page_all(
        shop, token, "webhooks.json", version, "webhooks", {"limit": 250}), errors, index)
    collect(args.out, "script_tags", lambda: page_all(
        shop, token, "script_tags.json", version, "script_tags", {"limit": 250}),
        errors, index)
    collect(args.out, "carrier_services", lambda: page_all(
        shop, token, "carrier_services.json", version, "carrier_services"), errors, index)
    collect(args.out, "fulfillment_services", lambda: page_all(
        shop, token, "fulfillment_services.json", version, "fulfillment_services"),
        errors, index)
    collect(args.out, "price_rules", lambda: page_all(
        shop, token, "price_rules.json", version, "price_rules", {"limit": 250}),
        errors, index)

    # Staff. read_users is a Shopify Plus / organization scope, so on a
    # standard plan this legitimately 403s - recorded, not swallowed, so the
    # report can say "not available on this plan" rather than implying an
    # empty staff list.
    collect(args.out, "staff_users", lambda: page_all(
        shop, token, "users.json", version, "users"), errors, index)

    # Installed apps, via GraphQL - there is no REST equivalent.
    try:
        gql = graphql(shop, token, version, """
        { appInstallations(first: 100) { edges { node {
            id
            app { id title developerName }
            accessScopes { handle }
            launchUrl
        } } } }""")
        write_json(args.out, "app_installations", gql)
        if gql.get("errors"):
            errors.append({"source": "graphql.appInstallations",
                           "error": json.dumps(gql["errors"])[:600]})
    except ShopifyError as exc:
        errors.append({"source": "graphql.appInstallations", "error": str(exc)[:600]})

    write_json(args.out, "_collection_metadata", {
        "collected_at": utcnow_iso(),
        "shop": shop,
        "api_version": version,
        "supported_versions": supported,
        "window_start": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_end": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "collections": index,
        "errors": errors,
        "coverage_caveats": [
            "The Event API covers only Article, Blog, Comment, CustomCollection, "
            "Order, Page, PriceRule and Product. Settings changes, app installs, "
            "payout and bank detail changes and staff changes are NOT in it.",
            "The store activity log (Settings > General > Store activity log) holds "
            "those settings changes. It caps at 250 entries, cannot be exported and "
            "is not exposed by any API - it must be captured by hand, and it rolls "
            "off as the store stays busy.",
            "Staff login history is the five most recent sessions per staff member "
            "and is deleted along with the staff member. A removed former owner's "
            "login history is therefore already gone.",
            "The user management activity log (Settings > Users > Security) records "
            "user and role changes but is an organization-level feature not available "
            "on every plan.",
        ],
    })
    if errors:
        log("%d collection errors recorded in _collection_metadata.json" % len(errors))
    return 0


if __name__ == "__main__":
    sys.exit(main())
