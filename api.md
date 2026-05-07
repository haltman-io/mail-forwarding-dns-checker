# API Documentation: DNS Validation Service

This document is generated from the current codebase and is intended for front-end integration.

## Base URL
- `http://<host>:<port>` (default: `http://localhost:3000`)

## Content Type
- All POST endpoints require `Content-Type: application/json`.
- If missing or incorrect, the API returns `415` with `{ "error": "unsupported_media_type" }`.

---

## Authentication (Optional for GET /api/checkdns/:target)
If `CHECKDNS_TOKEN` is set in `.env`, you must pass:

- Header: `x-api-key: <CHECKDNS_TOKEN>`

If missing or incorrect: `401` with `{ "error": "unauthorized" }`.

---

## Domain Normalization & Validation
Applied to POST bodies and `:target` path param.

- Input is trimmed and lowercased.
- Trailing dot is removed for storage (e.g., `example.com.` → `example.com`).
- Must be ASCII only (IDNs must be punycode, e.g. `xn--`).
- Total length <= 253, each label length 1..63.
- Allowed characters per label: `a-z`, `0-9`, `-`.
- Labels cannot start/end with `-`.
- Must not be a URL, IP, or include ports, paths, query, or fragment.

If invalid: `400` with a technical error message.

---

## Rate Limiting & Throttles
- Per-IP rate limiting: **60 requests/minute** (in-memory).
  - Exceeding returns: `429` with `{ "error": "rate_limited", "message": "Too many requests" }`.
- Per-target cooldown: `TARGET_COOLDOWN_SECONDS` (default 60s).
  - Returns `429` with `{ "error": "target is in cooldown window" }`.
- Max active jobs: `MAX_ACTIVE_JOBS` (default 100).
  - Returns `503` with `{ "error": "server_busy", "message": "Too many active jobs" }`.

---

## Status Values
- `PENDING`: waiting for DNS to meet requirements.
- `ACTIVE`: DNS requirements satisfied.
- `EXPIRED`: older than `DNS_JOB_MAX_AGE_HOURS` (default 24h).
- `FAILED`: reserved for permanent failures (not currently used automatically).

---

# 1) POST /request/ui

**Purpose:** Start UI DNS validation.

### Request Body
```json
{
  "target": "example.com"
}
```

### Success Responses
- `202 Accepted` (most common) or `200 OK` if already correct:
```json
{
  "id": 1,
  "target": "example.com",
  "type": "UI",
  "status": "PENDING",
  "expires_at": "2026-01-30T08:10:18.770Z"
}
```

### UI Requirements
For the apex domain (`example.com`):
1. CNAME record for `example.com` must satisfy:
   - `UI_CNAME_EXPECTED` (default `forward.haltman.io`), or
   - if `UI_CNAME_AUTHORIZED_IPS` is set, the CNAME chain must resolve to one of those IPs.

### Error Responses
- `400` invalid input
- `409` duplicate (same `target` + `type`)
- `415` missing/incorrect JSON content-type
- `429` cooldown or rate limit
- `503` too many active jobs
- `500` internal error

---

# 2) POST /request/email

**Purpose:** Start email forwarding DNS validation.

### Request Body
```json
{
  "target": "example.com"
}
```

### Success Responses
- `202 Accepted` (most common) or `200 OK` if already correct:
```json
{
  "id": 1,
  "target": "example.com",
  "type": "EMAIL",
  "status": "PENDING",
  "expires_at": "2026-01-30T08:10:18.770Z"
}
```

### Email Requirements
For the apex domain (`example.com`):
1. MX record includes:
   - `EMAIL_MX_EXPECTED_HOST` (default `mail.abin.lat`)
   - `EMAIL_MX_EXPECTED_PRIORITY` (default `10`)
2. TXT (SPF) must **exactly** match:
   - `EMAIL_SPF_EXPECTED` (default `v=spf1 include:_spf.abin.lat mx -all`)
3. TXT (DMARC) at `_dmarc.example.com` must **exactly** match:
   - `EMAIL_DMARC_EXPECTED` (default `v=DMARC1; p=none`)
4. DKIM CNAME at `<EMAIL_DKIM_SELECTOR>._domainkey.example.com` must match:
   - `EMAIL_DKIM_CNAME_EXPECTED` (default `s1._domainkey.dkim.abin.lat`)

### Error Responses
- `400` invalid input
- `409` duplicate (same `target` + `type`)
- `415` missing/incorrect JSON content-type
- `429` cooldown or rate limit
- `503` too many active jobs
- `500` internal error

---

# 3) GET /api/checkdns/:target

**Purpose:** Poll for status & missing DNS items for UI and/or EMAIL validation.

### Request
```
GET /api/checkdns/example.com
```

### Optional Header (if enabled)
```
x-api-key: <CHECKDNS_TOKEN>
```

### Response
```json
{
  "target": "example.com",
  "normalized_target": "example.com",
  "summary": {
    "has_ui": true,
    "has_email": true,
    "overall_status": "PENDING",
    "expires_at_min": "2026-01-30T08:10:18.770Z",
    "last_checked_at_max": "2026-01-29T08:12:18.770Z",
    "next_check_at_min": "2026-01-29T08:17:18.770Z"
  },
  "ui": {
    "status": "PENDING",
    "id": 1,
    "created_at": "2026-01-29T08:10:18.770Z",
    "expires_at": "2026-01-30T08:10:18.770Z",
    "last_checked_at": "2026-01-29T08:12:18.770Z",
    "next_check_at": "2026-01-29T08:17:18.770Z",
    "missing": [
      {
        "key": "CNAME",
        "type": "CNAME",
        "name": "example.com",
        "expected": "forward.haltman.io",
        "found": ["some.other.host"],
        "ok": false,
        "found_truncated": false
      }
    ]
  },
  "email": {
    "status": "PENDING",
    "id": 2,
    "created_at": "2026-01-29T08:10:18.770Z",
    "expires_at": "2026-01-30T08:10:18.770Z",
    "last_checked_at": "2026-01-29T08:12:18.770Z",
    "next_check_at": "2026-01-29T08:17:18.770Z",
    "missing": [
      {
        "key": "MX",
        "type": "MX",
        "name": "example.com",
        "expected": { "host": "mail.abin.lat", "priority": 10 },
        "found": [{ "exchange": "mx.example.net", "priority": 10 }],
        "ok": false,
        "found_truncated": false
      }
    ]
  }
}
```

### Notes
- If no UI or EMAIL row exists for that target: `404` with `{ "error": "not_found", "target": "example.com" }`.
- If no prior DNS check exists, the endpoint may perform a **single read-only DNS check** but only if:
  - `last_checked_at` is older than `CHECKDNS_MIN_INTERVAL_SECONDS`, and
  - it hasn’t checked recently for that target and row type in memory.
- If throttled, it returns a fallback “missing” list with empty `found`.

### overall_status
- `PENDING` if any existing row is pending.
- Otherwise `FAILED` if any existing row failed.
- Otherwise `EXPIRED` if any existing row expired.
- Otherwise `ACTIVE` when all existing rows are active.

---

## Error Response Shape
All errors:
```json
{ "error": "..." }
```

Examples:
- `415` → `{ "error": "unsupported_media_type" }`
- `400` invalid JSON → `{ "error": "invalid_json" }`
- `400` validation → `{ "error": "target must be a domain name without scheme" }`
- `401` unauthorized → `{ "error": "unauthorized" }`
- `409` duplicate → `{ "error": "Duplicate request for EMAIL example.com" }`
- `429` rate limit → `{ "error": "rate_limited", "message": "Too many requests" }`
- `429` cooldown → `{ "error": "target is in cooldown window" }`
- `503` → `{ "error": "server_busy", "message": "Too many active jobs" }`
- `500` → `{ "error": "internal_error" }`

---

## DNS “Missing” Structure

### UI missing
```json
[
  {
    "key": "CNAME",
    "type": "CNAME",
    "name": "example.com",
    "expected": "forward.haltman.io",
    "found": ["some.other.host"],
    "ok": false,
    "found_truncated": false
  }
]
```

### Email missing
```json
[
  {
    "key": "MX",
    "expected": { "host": "mail.abin.lat", "priority": 10 },
    "found": [{ "exchange": "mx.example.net", "priority": 10 }],
    "ok": false,
    "found_truncated": false
  },
  {
    "key": "SPF",
    "expected": "v=spf1 include:_spf.abin.lat mx -all",
    "found": ["v=spf1 include:_spf.google.com ~all"],
    "ok": false,
    "found_truncated": false
  },
  {
    "key": "DMARC",
    "expected": "v=DMARC1; p=none",
    "found": ["v=DMARC1; p=reject"],
    "ok": false,
    "found_truncated": false
  }
]
```

If records are excessive or too long, `found_truncated: true`.

---

## Examples (curl)

### UI request
```bash
curl -X POST http://localhost:3000/request/ui \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com"}'
```

### Email request
```bash
curl -X POST http://localhost:3000/request/email \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com"}'
```

### Check DNS (no token)
```bash
curl http://localhost:3000/api/checkdns/example.com
```

### Check DNS (token required)
```bash
curl http://localhost:3000/api/checkdns/example.com \
  -H "x-api-key: YOUR_TOKEN"
```

---

## Examples (JavaScript / Fetch)

### POST /request/email
```js
async function requestEmail(target) {
  const res = await fetch('http://localhost:3000/request/email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target })
  });
  const data = await res.json();
  if (!res.ok) throw data;
  return data;
}
```

### POST /request/ui
```js
async function requestUi(target) {
  const res = await fetch('http://localhost:3000/request/ui', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target })
  });
  const data = await res.json();
  if (!res.ok) throw data;
  return data;
}
```

### GET /api/checkdns/:target
```js
async function checkDns(target, token) {
  const headers = token ? { 'x-api-key': token } : {};
  const res = await fetch(`http://localhost:3000/api/checkdns/${encodeURIComponent(target)}`, {
    headers
  });
  const data = await res.json();
  if (!res.ok) throw data;
  return data;
}
```

---

## Polling Guidance
- Recommended polling interval: match server config (default 300s).
- Do not poll more frequently than `CHECKDNS_MIN_INTERVAL_SECONDS`.
- Stop polling when:
  - `status === "ACTIVE"` or `status === "EXPIRED"`, or
  - `summary.overall_status` is `ACTIVE`, `EXPIRED`, or `FAILED`.
- Use `next_check_at` to schedule your next poll.

---

## Integration Notes
- Store and reuse the normalized `target` returned by the API.
- Do not submit URL-like values (e.g., `https://example.com`).
- DNS propagation can take time; expect `PENDING` for minutes or hours.
- ASCII-only domains are accepted; convert IDNs to punycode before sending.
