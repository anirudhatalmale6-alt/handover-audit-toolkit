"""Turn the raw exports into a unified timeline and a findings report.

Design note on the watchlists below: they match on substrings of the event
name, not on an exact enumeration. Google and Meta both rename and add audit
event types without notice, and an exact list quietly stops matching when
they do - which looks identical to "nothing happened". Substring matching
over-reports slightly, and over-reporting is the safe direction here.

Usage:
    python -m audittk.analyze --dir out --report out/REPORT.md \
        [--partner old.partner@domain.com] [--handover 2026-09-01]
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

from .common import emit, log, utcnow_iso, write_csv, write_json

# (substring, severity, why it matters)
ADMIN_WATCH = [
    ("DELETE_USER", "high", "A user account was deleted. Restorable for 20 days only."),
    ("SUSPEND_USER", "medium", "A user account was suspended."),
    ("ADMIN_PRIVILEGE", "high", "Admin rights were granted or revoked."),
    ("ASSIGN_ROLE", "high", "An admin role was assigned."),
    ("UNASSIGN_ROLE", "medium", "An admin role was removed."),
    ("CREATE_ROLE", "medium", "A custom admin role was created."),
    ("PRIVILEGE", "high", "Privileges were changed."),
    ("API_CLIENT_ACCESS", "high",
     "Domain-wide delegation was granted to an OAuth client. This gives an external "
     "app access to all users' data and survives a password change."),
    ("EMAIL_MONITOR", "high",
     "An email monitor was created. This silently copies a user's mail to another mailbox."),
    ("DATA_TRANSFER", "high", "A bulk data transfer of a user's Drive/mail was requested."),
    ("TRANSFER_DOCUMENT_OWNERSHIP", "high", "Document ownership was transferred."),
    ("CHANGE_PASSWORD", "medium", "A password was changed by an admin."),
    ("RECOVERY", "high",
     "A recovery email or phone was changed. This is the classic way to retain a way "
     "back into an account after handing over the password."),
    ("STRONG_AUTHENTICATION", "high", "Two-step verification enforcement was changed."),
    ("DOMAIN", "medium", "A domain or domain alias was added or removed."),
    ("APPLICATION", "medium", "A marketplace app or service was added, removed or reconfigured."),
    ("DELETE_GROUP", "medium", "A group was deleted."),
    ("CHANGE_DRIVE_SETTING", "medium", "Drive sharing settings were changed."),
    ("CHANGE_DOCS_SETTING", "medium", "Docs sharing settings were changed."),
    ("DELETE", "medium", "Something was deleted."),
    ("REMOVE", "low", "Something was removed."),
]

DRIVE_WATCH = [
    ("delete", "high", "A file was permanently deleted."),
    ("trash", "medium", "A file was moved to trash. Auto-purges after 30 days."),
    ("download", "medium", "A file was downloaded."),
    ("change_document_visibility", "high", "A document's visibility was changed."),
    ("change_user_access", "medium", "A document's sharing was changed."),
    ("change_document_access_scope", "high", "A document's access scope was changed."),
    ("change_owner", "high", "A document's owner was changed."),
    ("remove_from_folder", "low", "A file was moved out of a folder."),
]

LOGIN_WATCH = [
    ("suspicious", "high", "Google flagged this sign-in as suspicious."),
    ("gov_attack", "high", "Google warned of a government-backed attack on this account."),
    ("password_leak", "high", "Account disabled after a leaked password."),
    ("login_failure", "low", "A failed sign-in."),
    ("logout", "low", "A sign-out."),
    ("login_success", "low", "A successful sign-in."),
]

TOKEN_WATCH = [
    ("authorize", "medium", "A third-party app was authorised against an account."),
    ("revoke", "low", "A third-party app authorisation was revoked."),
]

ACCOUNT_WATCH = [
    ("2sv_disable", "high", "Two-step verification was turned off."),
    ("recovery_email_edit", "high", "A recovery email was changed."),
    ("recovery_phone_edit", "high", "A recovery phone was changed."),
    ("password_edit", "medium", "A password was changed by the user."),
    ("titanium_unenroll", "high", "A security key was unenrolled."),
]

FB_WATCH = [
    ("remove", "high", "Something or someone was removed from the business."),
    ("delete", "high", "Something was deleted."),
    ("unshare", "high", "An asset was unshared."),
    ("add_people", "high", "A person was added to the business."),
    ("add_admin", "high", "An admin was added."),
    ("update_role", "high", "Someone's role was changed."),
    ("permission", "high", "A permission was changed."),
    ("payment", "high", "A payment method or billing setting was changed."),
    ("credit", "high", "An ad credit line or funding source was changed."),
    ("owner", "high", "Ownership of an asset changed."),
    ("transfer", "high", "An asset was transferred."),
    ("share", "medium", "An asset was shared with another business."),
    ("create_system_user", "high", "A system user was created. System user tokens do not expire."),
    ("two_factor", "high", "A two-factor setting was changed."),
    ("claim", "medium", "An asset was claimed."),
    ("update", "low", "Something was updated."),
    ("add", "low", "Something was added."),
]

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def load(path, default=None):
    if not os.path.exists(path):
        return default if default is not None else []
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def classify(name, watch):
    """First matching substring wins, so order the watchlists most-specific first."""
    low = (name or "").lower()
    for needle, severity, why in watch:
        if needle.lower() in low:
            return severity, why
    return "info", ""


def gw_params(event):
    out = {}
    for p in event.get("parameters", []) or []:
        for key in ("value", "boolValue", "intValue"):
            if key in p:
                out[p.get("name")] = p[key]
                break
        else:
            if "multiValue" in p:
                out[p.get("name")] = "|".join(str(v) for v in p["multiValue"])
    return out


def gw_target(params):
    for key in ("USER_EMAIL", "doc_title", "GROUP_EMAIL", "DOMAIN_NAME", "APPLICATION_NAME",
                "app_name", "primary_email", "NEW_VALUE", "target_user", "OLD_VALUE"):
        if params.get(key):
            return str(params[key])
    return ""


def analyse_google(root, watchlists, timeline, findings):
    d = os.path.join(root, "google")
    if not os.path.isdir(d):
        return

    for fname in sorted(os.listdir(d)):
        if not (fname.startswith("activity_") and fname.endswith(".json")):
            continue
        app = fname[len("activity_"):-len(".json")]
        watch = watchlists.get(app, [])
        for rec in load(os.path.join(d, fname)):
            ident = rec.get("id", {}) or {}
            actor = rec.get("actor", {}) or {}
            for event in rec.get("events", []) or []:
                params = gw_params(event)
                severity, why = classify(event.get("name"), watch)
                timeline.append({
                    "timestamp": normalise_ts(ident.get("time")),
                    "platform": "google",
                    "source": app,
                    "actor": actor.get("email") or actor.get("profileId") or "",
                    "action": event.get("name"),
                    "target": gw_target(params),
                    "ip": rec.get("ipAddress", ""),
                    "severity": severity,
                    "note": why,
                    "detail": json.dumps(params, sort_keys=True)[:2000],
                })

    users = load(os.path.join(d, "users.json"))
    supers = [u for u in users if u.get("isAdmin")]
    delegated = [u for u in users if u.get("isDelegatedAdmin") and not u.get("isAdmin")]

    findings.append({
        "severity": "high" if len(supers) != 1 else "info",
        "platform": "google",
        "title": "Super administrators: %d" % len(supers),
        "detail": "Super admins: %s. Delegated admins: %s." % (
            ", ".join(u.get("primaryEmail", "?") for u in supers) or "none",
            ", ".join(u.get("primaryEmail", "?") for u in delegated) or "none"),
        "recommendation": ("Acceptance criterion 1 is met only if this list is exactly you. "
                           "A second super admin, including a break-glass account you do not "
                           "control, should be removed or its password reset."),
        "evidence": "google/users.json",
    })

    suspended = [u for u in users if u.get("suspended")]
    if suspended:
        findings.append({
            "severity": "medium", "platform": "google",
            "title": "%d suspended account(s) still present" % len(suspended),
            "detail": ", ".join(u.get("primaryEmail", "?") for u in suspended),
            "recommendation": "A suspended account still holds its Drive files and its licence. "
                              "Decide whether to transfer the data and then delete, or keep it "
                              "suspended deliberately.",
            "evidence": "google/users.json",
        })

    deleted = [u for u in load(os.path.join(d, "users_deleted.json"))
               if u.get("deletionTime")]
    for u in deleted:
        try:
            when = datetime.fromisoformat(u["deletionTime"].replace("Z", "+00:00"))
            deadline = when + timedelta(days=20)
            left = (deadline - datetime.now(timezone.utc)).days
        except Exception:  # noqa: BLE001
            deadline, left = None, None
        findings.append({
            "severity": "high", "platform": "google",
            "title": "Deleted user %s" % u.get("primaryEmail", u.get("id", "?")),
            "detail": "Deleted at %s.%s" % (
                u.get("deletionTime"),
                "" if left is None else
                " Restorable until roughly %s - %d day(s) left."
                % (deadline.date(), left)),
            "recommendation": ("Restore it now if you need the mail or Drive content. After the "
                               "20 day window Google cannot recover it."
                               if (left is None or left > 0) else
                               "The 20 day restore window has passed. The audit log still shows "
                               "what the account did, but the content is gone."),
            "evidence": "google/users_deleted.json",
        })

    tokens = load(os.path.join(d, "oauth_tokens.json"))
    risky = [t for t in tokens if any(
        s in " ".join(t.get("scopes", []) or [])
        for s in ("mail.google.com", "/auth/drive", "admin.directory", "gmail.modify",
                  "cloud-platform"))]
    if risky:
        findings.append({
            "severity": "high", "platform": "google",
            "title": "%d third-party app grant(s) with wide data access" % len(risky),
            "detail": "; ".join(
                "%s -> %s" % (t.get("_user"), t.get("displayText") or t.get("clientId"))
                for t in risky[:40]),
            "recommendation": ("These keep working after a password change. Revoke anything you "
                               "do not recognise from Admin console > Security > API controls > "
                               "App access control, and from each user's account permissions."),
            "evidence": "google/oauth_tokens.json",
        })

    asps = load(os.path.join(d, "app_passwords.json"))
    if asps:
        findings.append({
            "severity": "high", "platform": "google",
            "title": "%d app password(s) outstanding" % len(asps),
            "detail": "; ".join("%s: %s" % (a.get("_user"), a.get("name")) for a in asps[:40]),
            "recommendation": "App passwords bypass two-step verification and survive a password "
                              "change. Revoke every one you cannot account for.",
            "evidence": "google/app_passwords.json",
        })

    no_2sv = [u for u in users if u.get("isEnrolledIn2Sv") is False and not u.get("suspended")]
    if no_2sv:
        findings.append({
            "severity": "medium", "platform": "google",
            "title": "%d active account(s) without 2-step verification" % len(no_2sv),
            "detail": ", ".join(u.get("primaryEmail", "?") for u in no_2sv[:40]),
            "recommendation": "Enforce 2SV for the whole org unit.",
            "evidence": "google/users.json",
        })


def analyse_gcp(root, timeline, findings):
    d = os.path.join(root, "gcp")
    if not os.path.isdir(d):
        return

    for fname in ("audit_admin_activity.json", "audit_system_event.json",
                  "audit_data_access.json", "audit_policy_denied.json", "iam_changes.json"):
        for entry in load(os.path.join(d, fname)):
            proto = entry.get("protoPayload", {}) or {}
            auth = proto.get("authenticationInfo", {}) or {}
            req = proto.get("requestMetadata", {}) or {}
            method = proto.get("methodName", "")
            severity = "high" if any(k in method for k in (
                "SetIamPolicy", "keys.create", "CreateServiceAccountKey",
                "CreateServiceAccount", "DeleteServiceAccount",
                "delete", "Delete")) else "info"
            timeline.append({
                "timestamp": normalise_ts(entry.get("timestamp")),
                "platform": "gcp",
                "source": fname[:-len(".json")],
                "actor": auth.get("principalEmail", ""),
                "action": method,
                "target": proto.get("resourceName", ""),
                "ip": req.get("callerIp", ""),
                "severity": severity,
                "note": "",
                "detail": json.dumps(proto.get("serviceName", ""))[:500],
            })

    meta = load(os.path.join(d, "_collection_metadata.json"), {})
    da = ((meta or {}).get("data_access_logging") or {}).get("projects_with_audit_configs") or []
    if not da:
        findings.append({
            "severity": "medium", "platform": "gcp",
            "title": "Data Access audit logging appears to be off",
            "detail": "No project returned an auditConfig. Admin Activity logs (what was "
                      "changed) exist and are immutable, but there is no record of what was "
                      "read, queried or exported.",
            "recommendation": "Turn on Data Access logging now so that reads are recorded from "
                              "today forward. It cannot be applied retrospectively.",
            "evidence": "gcp/_collection_metadata.json",
        })

    for policy in load(os.path.join(d, "iam_policies.json")):
        owners = [m for b in (policy.get("bindings") or []) if b.get("role") == "roles/owner"
                  for m in (b.get("members") or [])]
        if len(owners) > 1:
            findings.append({
                "severity": "high", "platform": "gcp",
                "title": "Project %s has %d owners" % (policy.get("project"), len(owners)),
                "detail": ", ".join(owners),
                "recommendation": "Owner can delete the project and grant itself anything. "
                                  "Reduce this to you plus any service account that genuinely "
                                  "needs it.",
                "evidence": "gcp/iam_policies.json",
            })

    # Cloud Logging writes the IAM admin methods under their gRPC names
    # (google.iam.admin.v1.CreateServiceAccountKey), not under the REST path
    # (projects.serviceAccounts.keys.create). Match both - an earlier version
    # of this check only matched the REST spelling and silently found nothing.
    keys = [t for t in timeline
            if t["platform"] == "gcp"
            and any(k in (t["action"] or "")
                    for k in ("keys.create", "CreateServiceAccountKey"))]
    if keys:
        findings.append({
            "severity": "high", "platform": "gcp",
            "title": "%d service account key(s) created in the window" % len(keys),
            "detail": "; ".join("%s by %s on %s" % (k["target"], k["actor"], k["timestamp"])
                                for k in keys[:30]),
            "recommendation": "A downloaded service account key is long-lived credentials that "
                              "no password change revokes. Delete any key you did not create.",
            "evidence": "gcp/iam_changes.json",
        })


def analyse_facebook(root, timeline, findings):
    d = os.path.join(root, "facebook")
    if not os.path.isdir(d):
        return

    for sub in sorted(os.listdir(d)):
        bdir = os.path.join(d, sub)
        if not (sub.startswith("business_") and os.path.isdir(bdir)):
            continue
        biz = sub[len("business_"):]

        for act in load(os.path.join(bdir, "activities.json")):
            severity, why = classify(act.get("event_type"), FB_WATCH)
            timeline.append({
                "timestamp": normalise_ts(act.get("event_time")),
                "platform": "facebook",
                "source": "business/%s" % biz,
                "actor": act.get("actor_name") or act.get("actor_id") or "",
                "action": act.get("event_type"),
                "target": "%s %s" % (act.get("object_type") or "",
                                     act.get("object_name") or act.get("object_id") or ""),
                "ip": "",
                "severity": severity,
                "note": why,
                "detail": (act.get("title") or "")[:500],
            })

        admins = [u for u in load(os.path.join(bdir, "business_users.json"))
                  if (u.get("role") or "").upper() in ("ADMIN", "FINANCE_EDITOR")]
        findings.append({
            "severity": "high" if len([a for a in admins
                                       if (a.get("role") or "").upper() == "ADMIN"]) != 1
            else "info",
            "platform": "facebook",
            "title": "Business %s: %d admin/finance user(s)" % (biz, len(admins)),
            "detail": "; ".join("%s (%s) %s" % (u.get("name"), u.get("role"), u.get("email") or "")
                                for u in admins) or "none",
            "recommendation": "Acceptance criterion 1 is met only if the admin list is exactly "
                              "you. Finance editors can see and change billing.",
            "evidence": "facebook/%s/business_users.json" % sub,
        })

        pending = load(os.path.join(bdir, "pending_users.json"))
        if pending:
            findings.append({
                "severity": "high", "platform": "facebook",
                "title": "Business %s: %d outstanding invitation(s)" % (biz, len(pending)),
                "detail": "; ".join("%s as %s" % (p.get("email"), p.get("role"))
                                    for p in pending),
                "recommendation": "An unaccepted invite is future access. Cancel any you did not "
                                  "send - the invite link works for whoever holds it.",
                "evidence": "facebook/%s/pending_users.json" % sub,
            })

        sysusers = load(os.path.join(bdir, "system_users.json"))
        if sysusers:
            findings.append({
                "severity": "high", "platform": "facebook",
                "title": "Business %s: %d system user(s)" % (biz, len(sysusers)),
                "detail": "; ".join("%s (%s)" % (s.get("name"), s.get("role"))
                                    for s in sysusers),
                "recommendation": "System user tokens do not expire and are not tied to anyone's "
                                  "login. This is the most common way access is retained after a "
                                  "person leaves. Regenerate or delete any you did not create.",
                "evidence": "facebook/%s/system_users.json" % sub,
            })

        for edge, label in (("agencies", "partner business with access to your assets"),
                            ("client_ad_accounts", "ad account owned by someone else"),
                            ("client_pages", "page owned by someone else")):
            rows = load(os.path.join(bdir, edge + ".json"))
            if rows:
                findings.append({
                    "severity": "medium", "platform": "facebook",
                    "title": "Business %s: %d %s" % (biz, len(rows), label),
                    "detail": "; ".join("%s (%s)" % (r.get("name"), r.get("id")) for r in rows[:30]),
                    "recommendation": "Confirm each of these relationships is one you want to "
                                      "keep. A partner business retains access independently of "
                                      "any individual person's account.",
                    "evidence": "facebook/%s/%s.json" % (sub, edge),
                })

        for edge in ("initiated_audience_sharing_requests",
                     "received_audience_sharing_requests"):
            rows = load(os.path.join(bdir, edge + ".json"))
            if rows:
                findings.append({
                    "severity": "high", "platform": "facebook",
                    "title": "Business %s: %d audience sharing request(s) (%s)"
                             % (biz, len(rows), edge.split("_")[0]),
                    "detail": json.dumps(rows[:10])[:1500],
                    "recommendation": "Custom audiences are customer data. Revoke any share with "
                                      "a business you do not recognise.",
                    "evidence": "facebook/%s/%s.json" % (sub, edge),
                })

        assigned = load(os.path.join(bdir, "asset_assignments.json"))
        known = {u.get("id") for u in load(os.path.join(bdir, "business_users.json"))}
        known |= {u.get("id") for u in load(os.path.join(bdir, "system_users.json"))}
        orphan = [a for a in assigned if a.get("user_id") and a["user_id"] not in known]
        if orphan:
            findings.append({
                "severity": "high", "platform": "facebook",
                "title": "Business %s: %d asset assignment(s) to identities not in the user list"
                         % (biz, len(orphan)),
                "detail": "; ".join("%s -> %s (%s)" % (a.get("user_name"), a.get("asset_name"),
                                                       a.get("tasks")) for a in orphan[:30]),
                "recommendation": "Someone holds permission on an asset without appearing as a "
                                  "business user. Remove the assignment directly on the asset.",
                "evidence": "facebook/%s/asset_assignments.json" % sub,
            })


def normalise_ts(value):
    """Return one sortable UTC ISO string from the shapes the sources emit.

    Meta sends unix seconds, Google Workspace sends RFC3339 with milliseconds,
    Cloud Logging sends RFC3339 with nanoseconds. Left as-is they sort against
    each other inconsistently at equal seconds, so everything is truncated to
    whole seconds in UTC.
    """
    if value in (None, ""):
        return ""
    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value, timezone.utc)
    else:
        text = str(value).strip()
        if text.isdigit():
            dt = datetime.fromtimestamp(int(text), timezone.utc)
        else:
            try:
                dt = datetime.fromisoformat(text.replace("Z", "+00:00").replace("+0000", "+00:00"))
                dt = dt.astimezone(timezone.utc)
            except ValueError:
                return text  # unparseable: keep it verbatim rather than drop it
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def render_report(path, findings, timeline, args, stats):
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    lines = []
    w = lines.append
    w("# IT handover audit - findings report")
    w("")
    w("Generated %s" % utcnow_iso())
    if args.handover:
        w("")
        w("Handover date supplied: %s" % args.handover)
    if args.partner:
        w("")
        w("Departing partner identifiers: %s" % ", ".join(args.partner))
    w("")
    w("## How to read this")
    w("")
    w("Every claim below points at a file in the archive. The archive is hashed in "
      "`MANIFEST.sha256`; re-run `python -m audittk.manifest --dir out --verify` at any "
      "point to prove nothing has been edited since collection.")
    w("")
    w("An empty section means the export contained no matching records. Where a log was "
      "unavailable rather than empty, that is recorded in the relevant "
      "`_collection_metadata.json` and repeated under Gaps below.")
    w("")

    w("## What was collected")
    w("")
    w("| Source | Records |")
    w("|---|---|")
    for key in sorted(stats):
        w("| %s | %s |" % (key, stats[key]))
    w("")

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    w("## Findings")
    w("")
    w("%s" % ", ".join("%d %s" % (counts[s], s) for s in
                       sorted(counts, key=lambda x: SEVERITY_ORDER.get(x, 9))) or "none")
    w("")
    for f in findings:
        w("### [%s] %s (%s)" % (f["severity"].upper(), f["title"], f["platform"]))
        w("")
        w(f["detail"] or "-")
        w("")
        w("Recommended: %s" % f["recommendation"])
        w("")
        w("Evidence: `%s`" % f["evidence"])
        w("")

    flagged = [t for t in timeline if t["severity"] in ("high", "medium")]
    w("## Notable events, most recent first")
    w("")
    w("Full timeline in `timeline.csv` (%d rows). %d rows are flagged high or medium; "
      "the 100 most recent are shown here." % (len(timeline), len(flagged)))
    w("")
    if flagged:
        w("| When | Platform | Actor | Action | Target | IP |")
        w("|---|---|---|---|---|---|")
        for t in flagged[:100]:
            w("| %s | %s | %s | %s | %s | %s |" % (
                t["timestamp"], t["platform"], t["actor"], t["action"],
                (t["target"] or "")[:60].replace("|", "/"), t["ip"]))
    w("")

    if args.partner:
        theirs = [t for t in timeline
                  if any(p.lower() in (t["actor"] or "").lower() for p in args.partner)]
        w("## Activity attributed to the departing partner")
        w("")
        w("%d event(s) matched. Full list in `timeline_partner.csv`." % len(theirs))
        w("")
        if theirs:
            w("| When | Platform | Action | Target | IP |")
            w("|---|---|---|---|---|")
            for t in theirs[:100]:
                w("| %s | %s | %s | %s | %s |" % (
                    t["timestamp"], t["platform"], t["action"],
                    (t["target"] or "")[:60].replace("|", "/"), t["ip"]))
        w("")

    if args.handover:
        w("## Activity after the handover date")
        w("")
        after = [t for t in timeline if t["timestamp"] and t["timestamp"][:10] >= args.handover]
        by_actor = {}
        for t in after:
            by_actor[t["actor"]] = by_actor.get(t["actor"], 0) + 1
        w("%d event(s) recorded on or after %s, by %d distinct actor(s)."
          % (len(after), args.handover, len(by_actor)))
        w("")
        w("| Actor | Events since handover |")
        w("|---|---|")
        for actor, n in sorted(by_actor.items(), key=lambda kv: -kv[1]):
            w("| %s | %d |" % (actor or "(unattributed)", n))
        w("")
        w("Any actor in this table other than you, your own service accounts and Google's "
          "or Meta's automated system identities is worth explaining.")
        w("")
        w("Note that one person can appear twice: Google identifies an actor by email "
          "address and Meta by display name, so the same individual shows up under both "
          "spellings. They are not two people.")
        w("")

    w("## Gaps and limits of this evidence")
    w("")
    w("These are properties of the platforms, not of the export:")
    w("")
    w("- Google retains most Workspace audit logs for 6 months. Anything older is "
      "unavailable, not absent.")
    w("- A deleted Workspace user is restorable for 20 days after deletion.")
    w("- Drive trash auto-purges 30 days after deletion; Google support can typically "
      "recover for around 25 days after that, via an admin request.")
    w("- GCP Data Access logs are off by default, so reads and exports may not be recorded.")
    w("- Meta's business activity log is short retention, on the order of 90 days.")
    w("- Actions taken directly inside a third-party tool that already holds a token are "
      "logged by that tool, not by Google or Meta.")
    w("")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    log("report written to %s (%d findings)" % (path, len(findings)))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Analyse the exports and write the report")
    ap.add_argument("--dir", default="out", help="root containing google/ gcp/ facebook/")
    ap.add_argument("--report", default=None)
    ap.add_argument("--partner", action="append", default=[],
                    help="departing partner email or id; repeatable")
    ap.add_argument("--handover", help="handover date, YYYY-MM-DD")
    args = ap.parse_args(argv)
    report_path = args.report or os.path.join(args.dir, "REPORT.md")

    watchlists = {
        "admin": ADMIN_WATCH, "drive": DRIVE_WATCH, "login": LOGIN_WATCH,
        "token": TOKEN_WATCH, "user_accounts": ACCOUNT_WATCH,
    }

    timeline, findings = [], []
    analyse_google(args.dir, watchlists, timeline, findings)
    analyse_gcp(args.dir, timeline, findings)
    analyse_facebook(args.dir, timeline, findings)

    for row in timeline:
        row["timestamp"] = normalise_ts(row["timestamp"])
    timeline.sort(key=lambda t: t["timestamp"] or "", reverse=True)

    stats = {}
    for row in timeline:
        key = "%s/%s" % (row["platform"], row["source"])
        stats[key] = stats.get(key, 0) + 1

    if timeline:
        write_csv(args.dir, "timeline", timeline)
    if args.partner:
        theirs = [t for t in timeline
                  if any(p.lower() in (t["actor"] or "").lower() for p in args.partner)]
        write_csv(args.dir, "timeline_partner", theirs or [{"timestamp": "", "platform": "",
                                                            "source": "", "actor": "",
                                                            "action": "", "target": "",
                                                            "ip": "", "severity": "",
                                                            "note": "", "detail": ""}])
    write_json(args.dir, "findings", findings)
    render_report(report_path, findings, timeline, args, stats)
    return 0


if __name__ == "__main__":
    sys.exit(main())
