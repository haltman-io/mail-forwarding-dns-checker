# Mail Forwarding Domain Check (Simple)

Simple Node.js service that accepts DNS validation requests and polls DNS until the requirements are met or the request expires.

## Setup

1) Install dependencies:
```
npm install
```

2) Create the database table:
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

## DNS Polling Behavior

- Requests are inserted with status `PENDING` and `expires_at = now + DNS_JOB_MAX_AGE_HOURS` (default 24h).
- An in-process background job checks DNS every `DNS_POLL_INTERVAL_SECONDS`.
- Jobs stop when the request becomes `ACTIVE` or `EXPIRED`.
- On restart, any pending, non-expired requests are resumed.

## /api/checkdns/:target

- Read-only endpoint for polling UI and/or EMAIL validation for the target.
- Returns the existing `ui` and `email` records and their missing items.
- If a row exists but has no `last_check_result_json` yet, the endpoint performs a single read-only DNS lookup for that row type to return a best-effort `missing` list. It does **not** create requests or start jobs.

## What ACTIVE Means

- UI: The target domain satisfies:
  - CNAME record for `<target>` matching `UI_CNAME_EXPECTED` (or resolving to `UI_CNAME_AUTHORIZED_IPS` when set)
- EMAIL: The target domain satisfies **all** of:
  - MX record with `EMAIL_MX_EXPECTED_HOST` and `EMAIL_MX_EXPECTED_PRIORITY`
  - SPF TXT record exactly matching `EMAIL_SPF_EXPECTED`
  - DMARC TXT record at `_dmarc.<target>` exactly matching `EMAIL_DMARC_EXPECTED`
  - DKIM CNAME record at `<EMAIL_DKIM_SELECTOR>._domainkey.<target>` matching `EMAIL_DKIM_CNAME_EXPECTED`
