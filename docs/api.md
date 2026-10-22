# Assay API Contract

All API endpoints return JSON. All responses are utf-8 encoded.

## Scan Endpoint

`GET /api/v1/scan?asset=CODE-ISSUER`

Scans an asset and returns its capability report.

### Response Headers

- `X-Assay-Undetermined`: Set to `true` when a scan is degraded due to an upstream source outage (such as failure to reach StellarExpert). When present, the response body contains `undetermined: true` and `undetermined_checks`, indicating that the source data was incomplete and the severity should be treated with caution.

### Status Codes

- `200 OK`: Successful scan (check `X-Assay-Undetermined` header or `undetermined` field for source degradation).
- `400 Bad Request`: Invalid asset code or issuer, or missing `?asset=` parameter. Also returned for an identifier naming the network's native asset — see below.
- `404 Not Found`: Asset not found on the ledger.
- `502 Bad Gateway`: Scan failed due to an underlying network or upstream error.

### The native asset

The native asset (XLM) has no issuer account, so there are no authorization
flags to read and nothing to classify. An identifier that names it — `native`
or `XLM`, in any case, with no issuer half — is answered with
`400 Bad Request` and an explicit message, never a parse error and never a
report:

```json
{ "error": "native asset has no issuer and no authorization flags: \"XLM\" cannot be scanned or attested" }
```

It is refused by design: the native asset is never scanned and never attested,
so it stays exactly what [integrating.md](integrating.md) already uses it as —
a never-attested asset the on-chain gate refuses. `GET /api/v1/history?asset=XLM`
returns the same `400` and message. A credit asset whose code merely happens
to be XLM (`XLM-G…`) is an ordinary asset and scans normally.
### Checking one holder's exposure: `holder=`

`GET /api/v1/scan?asset=CODE-ISSUER&holder=G...`

Without `holder`, a scan answers **"would I be exposed?"**: what the issuer can
do to a new holder, from the issuer's current flags. With `holder`, it also
answers **"am I exposed?"** for that one account. Under CAP-0035,
`is_clawback_enabled` is fixed on a trustline when the trustline is created,
so a holder who opened theirs before the issuer enabled clawback is not
exposed to it, even if the issuer's flag is set now. Issuer flags cannot tell
those two holders apart; the holder's own trustline can.

**Validation.** `holder` must be a Stellar account ID (`G…`, 56 characters).
Anything else is refused with `400 Bad Request` before any fetch:

```json
{ "error": "scan: invalid holder account ID: \"not-an-account\"" }
```

An empty `holder=` is the same as leaving it out.

**What changes in the report.** The scan reads the holder's trustline from
Horizon (`/accounts/{holder}`) and adds one finding, `check: "trustline"`
("Holder trustline flags"):

| Holder's trustline | Finding | Report |
| --- | --- | --- |
| `is_clawback_enabled: true` | Evidence quoting both trustline flags, and mechanic `trustline_clawback_enabled` | `mechanics` gains `trustline_clawback_enabled` |
| Not authorized (`is_authorized: false`) | Mechanic `trustline_deauthorized` | `mechanics` gains `trustline_deauthorized` |
| Authorized, no clawback | Evidence quoting both flags, no mechanic; the reasoning explains CAP-0035 grandfathering | Unchanged |
| The holder does not hold the asset | `undetermined: true`: there is no trustline to inspect | `undetermined: true`, `undetermined_checks` includes `trustline`, and the `X-Assay-Undetermined: true` header |
| Horizon could not be reached for the holder | `undetermined: true`, with a `not retrievable:` evidence claim | As above |

**`severity` never changes.** Severity is issuer-level and holder-independent
by design, so the same asset reports the same severity to every caller and an
on-chain gate reads a stable number. The holder answer is in the `trustline`
finding and in the two `trustline_*` mechanics only.

**Not for attestation.** A holder scan adds holder-specific evidence, so its
`evidence_hash` differs from the plain scan's, and a holder who does not hold
the asset makes the report undetermined. Attestations are always derived from
plain scans (`assay attestation` takes no holder).

Example: a holder whose trustline predates the issuer's clawback flag.

```sh
curl -s 'http://localhost:8080/api/v1/scan?asset=USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR&holder=GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H'
```

```json
{
  "severity": "high",
  "mechanics": ["auth_revocable", "auth_clawback_enabled"],
  "undetermined": false,
  "findings": [
    {
      "check": "trustline",
      "title": "Holder trustline flags",
      "severity": "clear",
      "undetermined": false,
      "mechanics": [],
      "reasoning": "Holder GBRP… has an authorized trustline with is_clawback_enabled=false. …"
    }
  ]
}
```

(Abridged: the report's other fields and findings are unchanged by `holder`.)
To check every trustline an account holds at once, use the
[exposure endpoint](#exposure-endpoint) below.

## Exposure Endpoint

`GET /api/v1/exposure?account=G...&limit=10&cursor=0`

Lists the trustlines an account holds and answers, per asset, with the asset's
issuer-level severity and its holder-trustline finding — the per-wallet form of
`?holder=` on the scan endpoint. **There is no aggregate or portfolio score:**
every asset carries its own severity and its own undetermined flag, and an
undetermined asset says nothing about any other asset on the page.

### Parameters

- `account` (required): the holder's `G...` address.
- `limit` (optional): page size, default `10`, clamped to a maximum of `50`.
  One page is up to `limit` full scans, which is why the bound exists.
- `cursor` (optional): index of the first trustline to return, for the next
  page. `0` starts; a cursor at or past the end returns an empty page.

### Response

- `account`, `total` (trustlines on the account), `limit` (page size applied),
  `count` (assets in this page), and `next_cursor` — absent on the last page.
- `assets[]`: per asset, `asset` (`code`/`issuer`), `severity`,
  `undetermined`, `undetermined_checks`, the `finding` from the holder-
  trustline check, and `reason` when that asset's scan failed outright (the
  `finding` is then absent rather than rendered as a clear answer).

### Status Codes

- `200 OK`: Page returned. Individual assets may be undetermined — see each
  entry's `undetermined` field; there is no header equivalent for a page.
- `400 Bad Request`: Missing or invalid `account`, `limit`, or `cursor`.
- `404 Not Found`: Account not found on the ledger.
- `429 Too Many Requests`: Rate limited. `Retry-After` gives the wait in
  seconds. Exposure is rate-limited per client address because one request
  runs a full scan per asset; `/api/v1/scan` is not affected.
- `502 Bad Gateway`: The account's trustline list could not be fetched.
