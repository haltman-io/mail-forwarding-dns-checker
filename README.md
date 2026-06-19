# Mail Forwarding Domain Check (Simple)

Simple Node.js service that accepts DNS validation requests and polls DNS until the requirements are met or the request expires.

## Setup

1) Install dependencies:
```
npm install
```

2) Create the database tables:
```
# adjust credentials/host as needed
mariadb -u root -p your_db_name < sql/schema.sql
```

3) Create `.env` from `.env.example` and fill in values.

## Security Notes

- Use a dedicated MariaDB user with least privilege. Grant only `SELECT`, `INSERT`, and `UPDATE` on the specific database/table used by this service.
- Optionally set `CHECKDNS_TOKEN` to require an `x-api-key` header for `/api/checkdns/:target`.

## Run

```
# production
npm start

# development (Node 20+)
npm run dev
```

Optional sanity check:
```
npm run sanity:domain
```

## API

### Request UI validation (CNAME only)
```
curl -X POST http://localhost:3000/request/ui \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com"}'
```

### Request Email forwarding validation (MX + SPF + DMARC + DKIM)
```
curl -X POST http://localhost:3000/request/email \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com"}'
```

### Poll status for a target
```
curl http://localhost:3000/api/checkdns/example.com
```

### Force stable rechecks
```
curl -X POST http://localhost:3000/api/recheckdns/all \
  -H "x-api-key: YOUR_CHECKDNS_TOKEN"

curl -X POST http://localhost:3000/api/recheckdns/example.com \
  -H "x-api-key: YOUR_CHECKDNS_TOKEN"
```

## DNS Polling Behavior

- Requests are inserted with status `PENDING` and `expires_at = now + DNS_JOB_MAX_AGE_HOURS` (default 24h).
- A new request for an existing `target` + `type` refreshes the existing row, clears stale DNS results, resets it to `PENDING`, extends `expires_at`, and immediately runs a fresh DNS check.
- An in-process background job checks DNS every `DNS_POLL_INTERVAL_SECONDS`.
- Jobs stop when the request becomes `ACTIVE` or `EXPIRED`.
- On restart, any pending, non-expired requests are resumed.
- The process logs every DNS check with the configured/system DNS servers, found records, pending requirements, and partial resolver errors.
- The process logs a general status summary every `DNS_STATUS_LOG_INTERVAL_SECONDS` seconds. Set it to `0` to disable.

## Domain Approval Columns

- A domain row is inserted only after a UI or EMAIL DNS validation succeeds.
- New domain rows use `DOMAIN_AUTO_APPROVE_ACTIVE` to decide the initial `active` value: `true` inserts `active=1`, `false` inserts `active=0`.
- UI DNS success sets `domain.active_ui = 1`.
- EMAIL DNS success sets `domain.active_mx = 1`.
- Failed UI or EMAIL DNS checks set the matching approval column to `0` only if the domain row already exists.
- Existing domain rows keep their current `active` value and the unrelated DNS approval column.

## Stable Domain Rechecks

- `dns_requests` remains the onboarding/request lifecycle table.
- `domain_dns_rechecks` tracks production rechecks for already-approved domain gates, keyed by `domain_id + type`.
- Successful UI or EMAIL approval creates or refreshes the matching recheck row.
- The recheck worker calls the same aggregate checker used by onboarding:
  - `UI` rechecks the CNAME rule.
  - `EMAIL` rechecks MX, SPF, DMARC, and DKIM together.
- A failed stable recheck first moves to `WARNING`, then `DEGRADED`, and only disables the matching DNS approval gate at `DNS_RECHECK_FAILURE_THRESHOLD`.
- Stable rechecks never change `domain.active`; that flag remains administrator-controlled.
- `sql/schema.sql` is the deploy schema for a new installation.
- `POST /api/recheckdns/all` and `POST /api/recheckdns/:target` force immediate stable rechecks through the same recheck state machine and require `CHECKDNS_TOKEN`.
- Forced rechecks send a start email and a completion summary email. Warning, degraded, disabled, and recovered emails can also be sent during the forced run.

## /api/checkdns/:target

- Polling endpoint for UI and/or EMAIL validation for the target.
- Returns the existing `ui` and `email` records and their missing items.
- If a row exists but has no `last_check_result_json` yet, the endpoint performs a single DNS lookup for that row type, stores the result, and returns a best-effort `missing` list. It does **not** create requests or start jobs.
- If a `PENDING` row has an existing result but `next_check_at` has already passed, the endpoint rechecks DNS once for that row type, stores the fresh result, and marks that row `ACTIVE` when its requirements are satisfied.

## What ACTIVE Means

- UI: The target domain satisfies:
  - CNAME record for `<target>` matching `UI_CNAME_EXPECTED` or resolving to `UI_CNAME_AUTHORIZED_IPS` when set
- EMAIL: The target domain satisfies **all** of:
  - MX record with `EMAIL_MX_EXPECTED_HOST` and `EMAIL_MX_EXPECTED_PRIORITY`
  - SPF TXT record exactly matching `EMAIL_SPF_EXPECTED`
  - DMARC TXT record at `_dmarc.<target>` exactly matching `EMAIL_DMARC_EXPECTED`
  - DKIM CNAME record at `<EMAIL_DKIM_SELECTOR>._domainkey.<target>` matching `EMAIL_DKIM_CNAME_EXPECTED`
