# Handover revocation checklist

You asked me to check and change every password associated with the accounts.
I can't do that part for you — I have no way to log into your dashboards, and
during a handover audit you shouldn't be handing every password to a contractor
anyway. So this is the list, in the order it needs doing.

**Changing passwords is the smallest part of this.** Every item marked
`SURVIVES PASSWORD CHANGE` below keeps working after you've reset every
password in the business. Those are the ones that actually matter.

---

## Phase 0 — before you revoke anything (today)

Revoking destroys some of the evidence. These four are cheap and take minutes.

- [ ] **Restore the deleted Google account.** admin.google.com → Directory →
      Users → filter "Recently deleted" → Recover. **20 days from deletion,
      then it's gone permanently.** Do this before anything else.
- [ ] **Screenshot the Shopify store activity log.** Settings → General →
      Store activity log. It caps at **250 entries**, can't be exported, and
      isn't in any API. It rolls off as the store stays busy — this record
      gets worse every day you leave it.
- [ ] **Screenshot her Shopify login history, if her staff account still
      exists.** Settings → Users and permissions → click her name → Recent
      access. It's the last five sessions with IPs. **Removing the staff
      account deletes this** — capture it before step 4.1.
- [ ] Run the export toolkit, or send me credentials so I can. Logs are easier
      to capture before you start changing things.

---

## Phase 1 — Google Workspace

- [ ] Reset your own super-admin password, and pick a new one not used anywhere
      else.
- [ ] Turn on 2-step verification on your own account first, before you lock
      anyone else out.
- [ ] **Check your own recovery email and phone.** Admin console → your account
      → Security. If a recovery address she controls is still set, every
      password you change can be undone by a reset. Check this on every admin
      account, not just yours.
- [ ] Users → her account → **Sign out user**. This kills live sessions; a
      password change alone doesn't always.
- [ ] Users → her account → Security → **App passwords → revoke all**.
      `SURVIVES PASSWORD CHANGE` — and they bypass 2FA.
- [ ] Users → her account → Security → **Connected applications → revoke**.
      `SURVIVES PASSWORD CHANGE`
- [ ] Do both of the above **for every user**, not just hers. The export lists
      them per user in `google/oauth_tokens.json` and `google/app_passwords.json`.
- [ ] Security → API controls → **Domain-wide delegation**. Remove any client
      ID you don't recognise. `SURVIVES PASSWORD CHANGE` — one entry here reads
      every mailbox in the domain.
- [ ] Apps → Google Workspace → Gmail → **Routing**, and check per-user
      forwarding. A forwarding rule copies mail out silently and isn't a
      login.
- [ ] Directory → Users → **remove her admin role**, then suspend rather than
      delete. Deleting starts a 20-day clock on her mailbox too, and you may
      still want it.
- [ ] Admin roles → confirm the super-admin list is exactly you.

## Phase 2 — Google Cloud (if you use it)

- [ ] IAM → remove her principal from every project.
- [ ] IAM → Service Accounts → **delete any key you didn't create**.
      `SURVIVES PASSWORD CHANGE` — a downloaded key file is permanent access
      with no login and no 2FA. `gcp/iam_changes.json` lists key creations.
- [ ] Check `roles/owner` is only you.
- [ ] Turn on **Data Access audit logging**. It's off by default, which is why
      there may be no record of what she read or exported. It can't be applied
      retroactively — this only helps from today.

## Phase 3 — Meta Business Manager

- [ ] Business Settings → People → **remove her**.
- [ ] Business Settings → **System Users → regenerate every token**.
      `SURVIVES PASSWORD CHANGE` — system user tokens don't expire and aren't
      tied to anyone's login. This is the most common way access is retained.
- [ ] Business Settings → **Pending invitations → cancel any you didn't send**.
      An unaccepted invite is future access and the link works for whoever
      holds it.
- [ ] Business Settings → Partners → **remove any partner business** you don't
      recognise. A partner business keeps access independently of any person.
- [ ] Check each **Page's roles directly** (Page → Settings → Page roles). A
      role granted on the Page itself sits outside Business Manager and
      survives removal from the business.
- [ ] Payment methods → confirm the card and billing contact are yours.
- [ ] Audience sharing → revoke shares to businesses you don't recognise.
      That's customer data leaving.

## Phase 4 — Shopify

- [ ] Settings → Users and permissions → **remove her staff account**
      (after Phase 0 screenshots).
- [ ] Settings → Users and permissions → **Collaborators**. Separate from
      staff, easy to miss, and a collaborator account keeps full access after
      the staff list looks clean.
- [ ] Settings → Apps and sales channels → **uninstall apps you don't
      recognise**. Uninstalling is what revokes an app's token —
      removing the person who installed it does not. `SURVIVES PASSWORD CHANGE`
- [ ] Settings → Apps and sales channels → **Develop apps**. Custom app tokens
      she created live here and never expire. `SURVIVES PASSWORD CHANGE`
- [ ] **Delete unknown webhooks.** They post your orders and customer data to
      whatever URL is set, forever. `shopify/webhooks.json`.
      `SURVIVES PASSWORD CHANGE`
- [ ] **Delete unknown script tags.** These run JavaScript on your storefront
      for every visitor — the mechanism used to skim checkout details.
      `shopify/script_tags.json`. `SURVIVES PASSWORD CHANGE`
- [ ] **Settings → Payments → check the payout bank account.** If one thing on
      this page is wrong, make it this one.
- [ ] Settings → Notifications → check where order notifications are sent.
- [ ] Change your own Shopify password and enable 2FA.

## Phase 5 — the ones people forget

These sit outside the three platforms and are usually how access actually
persists.

- [ ] **Domain registrar.** If she can move the domain, she can take the email
      and the store with it. Check the registrant contact and enable transfer
      lock.
- [ ] **DNS.** An added MX or TXT record can redirect or copy mail. Compare
      against what you expect.
- [ ] **Recovery email and phone on every account**, everywhere. This is the
      single most common leftover: every password you change can be reset by
      whoever controls the recovery address.
- [ ] Shared password manager / vault — remove her, then rotate everything that
      was in it. Her having left doesn't unsee what she saw.
- [ ] Payment processors: Stripe, PayPal, anything with a payout destination.
- [ ] Any phone number used for SMS 2FA that isn't yours.
- [ ] Email aliases, catch-all addresses and group memberships. An alias
      delivering to an outside address is invisible from the user list.

---

## Order of operations

1. Phase 0 today — evidence has expiry dates, access doesn't.
2. Your own account first: password, 2FA, recovery address. Lock yourself in
   before locking anyone out.
3. Then the `SURVIVES PASSWORD CHANGE` items. These are the real job.
4. Passwords last. They're the easy part and the least effective.

Work through it and tell me which items turned up something. Anything you find
goes into the written report with the log entry that corroborates it.
