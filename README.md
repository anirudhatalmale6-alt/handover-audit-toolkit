# Handover audit toolkit — Google Workspace / GCP / Meta Business Manager

Read-only extraction of Access, Security and Activity logs from both platforms,
plus a findings report and a SHA-256 manifest so the archive can be proved
unaltered later.

Nothing in this toolkit writes to your tenant. There is no delete, update or
create call anywhere in it — grep for `.delete(`, `.update(` or `.insert(` and
you will find none.

---

## What it produces

```
out/
  google/
    activity_admin.json / .csv        every change made in the Admin console
    activity_login.json               sign-ins, failures, suspicious-login flags
    activity_drive.json               file create / edit / delete / download / share
    activity_token.json               OAuth grants to third-party apps
    activity_user_accounts.json       2SV changes, recovery email/phone changes
    activity_<app>.json               groups, saml, calendar, chat, meet, gcp, ...
    users.json                        current accounts, admin flags, 2SV state
    users_deleted.json                deleted accounts still inside the 20-day window
    role_assignments.json             who holds which admin role
    oauth_tokens.json                 third-party app grants, per user
    app_passwords.json                app passwords (these bypass 2SV)
    _collection_metadata.json         window, scopes used, and every collection error
  gcp/
    audit_admin_activity.json         immutable _Required bucket, 400-day retention
    audit_data_access.json            only populated if Data Access logging was on
    audit_system_event.json
    audit_policy_denied.json
    iam_changes.json                  SetIamPolicy and service-account key events
    iam_policies.json                 current bindings + auditConfigs
    projects.json
    _collection_metadata.json
  facebook/
    business_<id>/
      activities.json                 the business activity log (Security Centre view)
      business_users.json             people and their roles
      system_users.json               non-expiring tokens
      pending_users.json              unaccepted invitations
      owned_/client_ ad accounts, pages, apps, pixels, instagram accounts
      agencies.json / clients.json    other businesses with access
      *_audience_sharing_requests.json
      asset_assignments.json          who holds which permission on which asset
    _collection_metadata.json
  timeline.csv                        every event from both platforms, one sheet
  timeline_partner.csv                filtered to the departing partner
  findings.json
  REPORT.md                           the written report
  MANIFEST.sha256 / MANIFEST.json     hash of every file above
```

---

## Install

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

Python 3.9+. The Facebook extractor uses only the standard library.

---

## 1. Google Workspace access

You create the credential; I never need your password.

1. In **console.cloud.google.com**, pick or create a project.
2. **APIs & Services → Library** → enable **Admin SDK API**.
3. **IAM & Admin → Service Accounts → Create service account**. Name it
   `handover-audit`. Skip the optional role steps.
4. Open it → **Keys → Add key → Create new key → JSON**. A file downloads.
   That file is the credential — send it to me, or keep it and run the scripts
   yourself.
5. On the service account's **Details** tab, copy the **Unique ID** (a long
   number, sometimes shown as the Client ID).
6. In **admin.google.com** → **Security → Access and data control → API
   controls → Manage Domain Wide Delegation → Add new**. Paste the Unique ID
   and these scopes as one comma-separated line:

```
https://www.googleapis.com/auth/admin.reports.audit.readonly,
https://www.googleapis.com/auth/admin.reports.usage.readonly,
https://www.googleapis.com/auth/admin.directory.user.readonly,
https://www.googleapis.com/auth/admin.directory.group.readonly,
https://www.googleapis.com/auth/admin.directory.group.member.readonly,
https://www.googleapis.com/auth/admin.directory.domain.readonly,
https://www.googleapis.com/auth/admin.directory.orgunit.readonly,
https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly,
https://www.googleapis.com/auth/admin.directory.device.mobile.readonly,
https://www.googleapis.com/auth/admin.directory.user.security
```

Every one of those ends in `.readonly` except the last. There is no readonly
variant of `admin.directory.user.security` — it is the only scope Google
offers for listing a user's OAuth tokens and app passwords, which is exactly
the leftover-access question this job is about. It is used for reads only here.

**This grant is revocable in one click.** When the audit is done, delete the
row from that Domain Wide Delegation screen and the credential is dead
immediately, regardless of who holds the key file.

```sh
python -m audittk.gw_export --key sa.json --admin you@yourdomain.com \
    --out out/google --days 180
```

`--days 180` is the practical maximum: Google retains most Workspace audit
logs for 6 months.

---

## 2. GCP access (skip if you do not use GCP beyond Workspace)

Grant the same service account, on each project you want covered:

- **Viewer** (`roles/viewer`)
- **Private Logs Viewer** (`roles/logging.privateLogViewer`) — without this the
  Data Access logs are invisible even when they exist

Then:

```sh
python -m audittk.gcp_export --key sa.json --out out/gcp --days 180
# or target explicitly:
python -m audittk.gcp_export --key sa.json --out out/gcp --days 180 \
    --project my-project --org 123456789012
```

---

## 3. Meta Business Manager access

1. **business.facebook.com → Business Settings → Users → System Users → Add**.
   Name it `handover-audit`, role **Admin**.
2. **Generate new token** → pick any app you own → select
   `business_management`, `ads_read`, `read_insights`.
3. Copy the token. It is shown once.

```sh
export FB_TOKEN='EAAG...'
python -m audittk.fb_export --out out/facebook --days 90
# or name the business explicitly:
python -m audittk.fb_export --business 1234567890 --out out/facebook --days 90
```

Meta's business activity log is short retention — on the order of 90 days — so
this export is the only durable copy you will have of it.

Revoke afterwards by deleting the system user in Business Settings.

The extractor calls `debug_token` first and prints the token's actual scopes.
A token missing `business_management` returns **empty lists rather than
errors**, which reads exactly like a clean history — so it warns loudly
instead.

---

## 4. Report and manifest

```sh
python -m audittk.analyze --dir out \
    --partner old.partner@yourdomain.com --handover 2026-09-01
python -m audittk.manifest --dir out
```

`--partner` accepts the departing partner's email or Meta user id and is
repeatable; it produces `timeline_partner.csv` and a dedicated report section.
`--handover` adds an "activity after this date, by actor" table.

`manifest` prints one root hash. Write it down somewhere outside the archive.
Any later change is then provable:

```sh
python -m audittk.manifest --dir out --verify
```

Output is `OK` with exit 0, or `CHANGED` / `MISSING` / `ADDED` per file with
exit 1.

---

## 5. Everything in one go

```sh
./run_all.sh sa.json you@yourdomain.com old.partner@yourdomain.com 2026-09-01
```

---

## Try it without any credentials

The toolkit ships with a fixture shaped like real API responses, so you can see
exactly what the output looks like before granting anything:

```sh
python tests/make_fixture.py tests/fixture
python -m audittk.analyze --dir tests/fixture \
    --partner old.partner@example.com --handover 2026-09-13
python -m audittk.manifest --dir tests/fixture
```

Then open `tests/fixture/REPORT.md`. The scenario is invented — the data is
not from anyone's tenant — but the record shapes and the analysis path are the
real ones.

---

## Limits of this evidence

These are properties of the platforms, not of the toolkit. They belong in the
report because an empty result has two very different meanings:

- Google retains most Workspace audit logs for **6 months**.
- A deleted Workspace user is restorable for **20 days** after deletion.
- Drive trash auto-purges **30 days** after deletion; Google support can
  typically recover for roughly **25 days** after that, by admin request.
- **GCP Data Access logs are off by default.** If they were never enabled there
  is a record of what was *changed* but none of what was *read or exported*.
  This cannot be applied retrospectively — turning it on today only helps from
  today.
- Meta's business activity log is short retention, on the order of **90 days**.
- Anything done inside a third-party tool that already holds a valid token is
  logged by that tool, not by Google or Meta.

## Note on "immutable"

Nothing you export to your own disk is truly immutable — the files are just
files. What the manifest gives you is **tamper-evidence**: an alteration after
collection becomes detectable, provided you keep the root hash somewhere
separate from the archive.

The one genuinely immutable record in scope is GCP's `_Required` log bucket,
which cannot be deleted or shortened by anyone, including a project owner. If
you need that property for the Workspace side too, Google Vault with a
retention rule is the supported route — worth setting up regardless, since it
is the only thing that protects the *next* six months.
