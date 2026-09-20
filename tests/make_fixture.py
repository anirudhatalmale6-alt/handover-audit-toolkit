"""Build a fake export tree shaped exactly like the real API responses.

Every record below is copied in shape from the documented response of the
API that produces it (Admin SDK Reports activities.list, Directory users.list
/ tokens.list, Cloud Logging entries.list, Graph /{business}/activities).
Running analyze.py over this proves the analysis path works before the
toolkit is ever pointed at a live tenant.

    python tests/make_fixture.py tests/fixture
    python -m audittk.analyze --dir tests/fixture --partner old.partner@example.com \
        --handover 2026-09-01
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone


def w(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def activity(app, when, actor, event_name, params, ip="203.0.113.10"):
    return {
        "kind": "admin#reports#activity",
        "id": {"time": when, "uniqueQualifier": str(abs(hash(when + event_name)) % 10**18),
               "applicationName": app, "customerId": "C01abc234"},
        "actor": {"email": actor, "profileId": "1122334455"},
        "ipAddress": ip,
        "events": [{"type": "USER_SETTINGS", "name": event_name,
                    "parameters": [{"name": k, "value": str(v)} for k, v in params.items()]}],
    }


def main(root):
    now = datetime.now(timezone.utc)
    def t(days_ago, hour=9):
        return (now - timedelta(days=days_ago)).replace(
            hour=hour, minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    partner = "old.partner@example.com"
    owner = "new.owner@example.com"
    g = os.path.join(root, "google")

    w(os.path.join(g, "activity_admin.json"), [
        activity("admin", t(3), partner, "DELETE_USER", {"USER_EMAIL": "finance@example.com"}),
        activity("admin", t(4), partner, "CREATE_EMAIL_MONITOR",
                 {"USER_EMAIL": owner, "EMAIL_MONITOR_DEST_EMAIL": "watcher@gmail.com"}),
        activity("admin", t(5), partner, "AUTHORIZE_API_CLIENT_ACCESS",
                 {"API_CLIENT_NAME": "1098765432109876543",
                  "API_SCOPES": "https://mail.google.com/"}),
        activity("admin", t(12), partner, "GRANT_ADMIN_PRIVILEGE",
                 {"USER_EMAIL": "contractor@example.com"}),
        activity("admin", t(40), owner, "CHANGE_APPLICATION_SETTING",
                 {"APPLICATION_NAME": "Drive", "NEW_VALUE": "SHARING_OUTSIDE_DOMAIN"}),
    ])
    w(os.path.join(g, "activity_drive.json"), [
        activity("drive", t(3, 11), partner, "delete",
                 {"doc_title": "2026 Client Contracts.xlsx", "doc_type": "spreadsheet"}),
        activity("drive", t(3, 12), partner, "trash",
                 {"doc_title": "Supplier pricing.pdf", "doc_type": "pdf"}),
        activity("drive", t(6), partner, "download",
                 {"doc_title": "Customer list master.csv", "doc_type": "csv"}),
        activity("drive", t(7), partner, "change_document_visibility",
                 {"doc_title": "Brand assets", "visibility_change": "external"}),
        activity("drive", t(30), owner, "edit", {"doc_title": "Notes.docx"}),
    ])
    w(os.path.join(g, "activity_login.json"), [
        activity("login", t(2), partner, "login_success", {"login_type": "google_password"},
                 ip="198.51.100.77"),
        activity("login", t(9), partner, "suspicious_login", {"login_challenge_status": "pass"},
                 ip="198.51.100.77"),
        activity("login", t(20), owner, "login_success", {"login_type": "google_password"}),
    ])
    w(os.path.join(g, "activity_token.json"), [
        activity("token", t(5), partner, "authorize",
                 {"client_id": "1098765432109876543", "app_name": "Backup Exporter",
                  "scope": "https://www.googleapis.com/auth/drive"}),
    ])
    w(os.path.join(g, "activity_user_accounts.json"), [
        activity("user_accounts", t(4, 14), partner, "recovery_email_edit",
                 {"new_value": "partner.personal@gmail.com"}),
        activity("user_accounts", t(4, 15), partner, "2sv_disable", {}),
    ])

    w(os.path.join(g, "users.json"), [
        {"primaryEmail": owner, "name": {"fullName": "New Owner"}, "isAdmin": True,
         "isDelegatedAdmin": False, "suspended": False, "isEnrolledIn2Sv": True,
         "lastLoginTime": t(0)},
        {"primaryEmail": partner, "name": {"fullName": "Old Partner"}, "isAdmin": True,
         "isDelegatedAdmin": False, "suspended": False, "isEnrolledIn2Sv": False,
         "lastLoginTime": t(2)},
        {"primaryEmail": "contractor@example.com", "name": {"fullName": "Contractor"},
         "isAdmin": False, "isDelegatedAdmin": True, "suspended": False,
         "isEnrolledIn2Sv": False, "lastLoginTime": t(11)},
        {"primaryEmail": "ops@example.com", "name": {"fullName": "Ops"}, "isAdmin": False,
         "isDelegatedAdmin": False, "suspended": True, "isEnrolledIn2Sv": True},
    ])
    w(os.path.join(g, "users_deleted.json"), [
        {"primaryEmail": "finance@example.com", "id": "9988776655",
         "deletionTime": t(3)},
    ])
    w(os.path.join(g, "oauth_tokens.json"), [
        {"_user": owner, "clientId": "1098765432109876543", "displayText": "Backup Exporter",
         "anonymous": False, "nativeApp": False,
         "scopes": ["https://www.googleapis.com/auth/drive", "https://mail.google.com/"]},
        {"_user": partner, "clientId": "222", "displayText": "Calendar Sync",
         "scopes": ["https://www.googleapis.com/auth/calendar.readonly"]},
    ])
    w(os.path.join(g, "app_passwords.json"), [
        {"_user": partner, "name": "Old phone mail", "creationTime": "1704067200000"},
    ])
    w(os.path.join(g, "role_assignments.json"), [
        {"roleAssignmentId": "1", "roleId": "SUPER_ADMIN", "assignedTo": "1122334455",
         "scopeType": "CUSTOMER"},
    ])

    gc = os.path.join(root, "gcp")
    w(os.path.join(gc, "iam_changes.json"), [
        {"timestamp": t(5), "protoPayload": {
            "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
            "resourceName": "projects/acme-prod/serviceAccounts/deploy@acme-prod.iam.gserviceaccount.com",
            "serviceName": "iam.googleapis.com",
            "authenticationInfo": {"principalEmail": partner},
            "requestMetadata": {"callerIp": "198.51.100.77"}}},
        {"timestamp": t(8), "protoPayload": {
            "methodName": "SetIamPolicy",
            "resourceName": "projects/acme-prod",
            "serviceName": "cloudresourcemanager.googleapis.com",
            "authenticationInfo": {"principalEmail": partner},
            "requestMetadata": {"callerIp": "198.51.100.77"}}},
    ])
    w(os.path.join(gc, "audit_admin_activity.json"), [
        {"timestamp": t(10), "protoPayload": {
            "methodName": "storage.buckets.delete",
            "resourceName": "projects/_/buckets/acme-archive",
            "serviceName": "storage.googleapis.com",
            "authenticationInfo": {"principalEmail": partner},
            "requestMetadata": {"callerIp": "198.51.100.77"}}},
    ])
    w(os.path.join(gc, "audit_data_access.json"), [])
    w(os.path.join(gc, "iam_policies.json"), [
        {"project": "acme-prod", "auditConfigs": [],
         "bindings": [
             {"role": "roles/owner", "members": ["user:%s" % owner, "user:%s" % partner]},
             {"role": "roles/editor", "members": ["serviceAccount:deploy@acme-prod.iam.gserviceaccount.com"]},
         ], "etag": "BwX"},
    ])
    w(os.path.join(gc, "_collection_metadata.json"), {
        "collected_at": t(0), "data_access_logging": {"projects_with_audit_configs": []},
    })

    fb = os.path.join(root, "facebook", "business_1234567890")
    unix = lambda days: int((now - timedelta(days=days)).timestamp())  # noqa: E731
    w(os.path.join(fb, "activities.json"), [
        {"event_time": unix(2), "event_type": "remove_people_from_business",
         "actor_name": "Old Partner", "actor_id": "77001", "object_type": "BUSINESS_USER",
         "object_name": "New Owner", "object_id": "77002",
         "title": "Removed New Owner from the business"},
        {"event_time": unix(4), "event_type": "update_ad_account_payment_method",
         "actor_name": "Old Partner", "actor_id": "77001", "object_type": "AD_ACCOUNT",
         "object_name": "Acme Main", "object_id": "act_555",
         "title": "Changed payment method"},
        {"event_time": unix(6), "event_type": "create_system_user",
         "actor_name": "Old Partner", "actor_id": "77001", "object_type": "SYSTEM_USER",
         "object_name": "Legacy Integration", "object_id": "77009",
         "title": "Created system user"},
        {"event_time": unix(30), "event_type": "update_business_info",
         "actor_name": "New Owner", "actor_id": "77002", "object_type": "BUSINESS",
         "object_name": "Acme", "object_id": "1234567890", "title": "Updated address"},
    ])
    w(os.path.join(fb, "business_users.json"), [
        {"id": "77002", "name": "New Owner", "email": owner, "role": "ADMIN"},
        {"id": "77001", "name": "Old Partner", "email": partner, "role": "ADMIN"},
        {"id": "77003", "name": "Bookkeeper", "email": "books@example.com",
         "role": "FINANCE_EDITOR"},
    ])
    w(os.path.join(fb, "system_users.json"), [
        {"id": "77009", "name": "Legacy Integration", "role": "ADMIN", "created_by": "77001"},
    ])
    w(os.path.join(fb, "pending_users.json"), [
        {"id": "77010", "email": "someone@outside.com", "role": "ADMIN",
         "expiration_time": "2026-12-01T00:00:00+0000"},
    ])
    w(os.path.join(fb, "owned_ad_accounts.json"), [
        {"id": "act_555", "name": "Acme Main", "account_status": 1},
    ])
    w(os.path.join(fb, "client_ad_accounts.json"), [])
    w(os.path.join(fb, "agencies.json"), [
        {"id": "999", "name": "Partner Media Ltd", "verification_status": "verified"},
    ])
    w(os.path.join(fb, "initiated_audience_sharing_requests.json"), [
        {"id": "42", "request_status": "APPROVED", "receiving_business": {"id": "999"}},
    ])
    w(os.path.join(fb, "received_audience_sharing_requests.json"), [])
    w(os.path.join(fb, "asset_assignments.json"), [
        {"asset_type": "owned_ad_accounts", "asset_id": "act_555", "asset_name": "Acme Main",
         "user_id": "77001", "user_name": "Old Partner", "tasks": ["MANAGE"]},
        {"asset_type": "owned_ad_accounts", "asset_id": "act_555", "asset_name": "Acme Main",
         "user_id": "88888", "user_name": "Unknown Identity", "tasks": ["MANAGE", "ADVERTISE"]},
    ])
    # Shopify. Event records use `verb` + `subject_type` and carry `author`
    # as a display name only - there is no email on a Shopify event, which is
    # why the timeline cannot join it to a Google actor automatically.
    sh = os.path.join(root, "shopify")
    def ev(days_ago, verb, subject_type, subject_id, author, message):
        return {"id": abs(hash(message)) % 10**9, "subject_id": subject_id,
                "subject_type": subject_type, "verb": verb, "author": author,
                "message": message,
                "created_at": (now - timedelta(days=days_ago)).strftime(
                    "%Y-%m-%dT%H:%M:%S+00:00")}

    w(os.path.join(sh, "events.json"), [
        ev(3, "destroy", "Product", 7001, "Old Partner", "Product was deleted"),
        ev(4, "update", "Product", 7002, "Old Partner", "Product was updated"),
        ev(5, "destroy", "Page", 8001, "Old Partner", "Page was deleted"),
        ev(9, "cancel", "Order", 9001, "Old Partner", "Order was cancelled"),
        ev(25, "create", "Product", 7003, "New Owner", "Product was created"),
    ])
    w(os.path.join(sh, "events_deletions.json"), [
        dict(ev(3, "destroy", "Product", 7001, "Old Partner", "Product was deleted"),
             _resource="Product"),
        dict(ev(5, "destroy", "Page", 8001, "Old Partner", "Page was deleted"),
             _resource="Page"),
    ])
    w(os.path.join(sh, "webhooks.json"), [
        {"id": 1, "topic": "orders/create", "address": "https://hooks.partner-personal.net/orders",
         "format": "json", "created_at": t(40)},
        {"id": 2, "topic": "app/uninstalled", "address": "https://shopifyapp.example.com/hook",
         "format": "json", "created_at": t(200)},
    ])
    w(os.path.join(sh, "script_tags.json"), [
        {"id": 5, "src": "https://cdn.partner-personal.net/track.js",
         "display_scope": "all", "created_at": t(38)},
    ])
    w(os.path.join(sh, "staff_users.json"), [])
    w(os.path.join(sh, "app_installations.json"), {"data": {"appInstallations": {"edges": [
        {"node": {"id": "gid://shopify/AppInstallation/1",
                  "app": {"id": "gid://shopify/App/1", "title": "Order Exporter",
                          "developerName": "Unknown Dev"},
                  "accessScopes": [{"handle": "read_orders"}, {"handle": "read_customers"}]}},
    ]}}})
    w(os.path.join(sh, "shop.json"), {"name": "Acme Store", "plan_name": "basic",
                                      "myshopify_domain": "acme.myshopify.com"})
    w(os.path.join(sh, "_collection_metadata.json"), {
        "collected_at": t(0), "shop": "acme.myshopify.com", "api_version": "2025-01",
        "collections": {"staff_users": {"records": None,
                                        "status": "HTTP 403: read_users scope not granted"}},
    })

    print("fixture written to %s" % root)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "tests/fixture")
