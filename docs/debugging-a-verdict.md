# Debugging a surprising verdict

When Assay reports something unexpected for an asset, you need a systematic way to investigate why the scanner reached that conclusion. A surprising verdict usually stems from one of two root causes:

1. **"The source says so" (Correct-but-surprising)** — The live data source (Horizon, `stellar.toml`, or StellarExpert) actually contains the flag or state that triggered the verdict, even if it contradicts the reader's expectation.
2. **Code bug** — Assay's check misread or misinterpreted valid source data.

> [!IMPORTANT]
> If you discover a way to make Assay under-report risk, that is a security issue. Do not open a public issue — report it privately per [SECURITY.md](../SECURITY.md) and [CONTRIBUTING.md](../CONTRIBUTING.md).

## Ground rules

- **Severity is capability-only**: Severity measures what the issuer *can* do to a holder's balance (consensus-enforced flags), not a prediction of intent, age, or reputation.
- **Never display a value you did not fetch**: Every finding is backed by attributed evidence lines containing exact URLs and retrieved timestamps.
- **Never re-derive a consumed signal**: Third-party reputation signals (StellarExpert directory and blocklists) are passed through as external evidence; Assay does not maintain its own scam lists.
- **Accountability is reported, never discounted**: Reciprocal domain verification (`verified`, `unverified`, `unknown`) informs a human and never lowers severity.

---

## Step 1: Reproduce and read the report (`./assay scan CODE-ISSUER`)

Run `./assay scan CODE-ISSUER` to generate the complete JSON report from a live scan:

```sh
./assay scan CODE-ISSUER
```

Examine the fields in the report:
- `severity` and `base_severity`: The assigned severity level (`clear`, `low`, `medium`, `high`, `critical`) and whether it was raised by reputation escalation.
- `accountability`: The reciprocal domain verification status (`verified`, `unverified`, `unknown`).
- `state`: The overall scan state (`valid`, `unknown`, `stale`). An undetermined scan has `state: "unknown"`.
- `undetermined` and `undetermined_checks`: Whether any check failed to complete because a dependency/source was unreachable (`undetermined: true`), and the list of check IDs that could not complete. When true, the report is partial.
- `findings`: The list of findings produced by each check (`capability`, `mutability`, `sep1-domain`, `reputation`), including their prose reasoning and assigned mechanics.
- `evidence`: The raw attributed evidence items, each containing a `source`, `url`, `claim`, and `retrieved_at` timestamp. When a source cannot be reached, `attempted: true` is recorded with the connection failure claim.

### Worked example 1: Medium severity by capability (USDC - Captured 2026-09-28)

Run `./assay scan` for USDC (`USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN`):

```sh
./assay scan USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN
```

Captured output:

```json
{
  "asset": {
    "code": "USDC",
    "issuer": "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
  },
  "severity": "medium",
  "base_severity": "medium",
  "escalated": false,
  "accountability": "unverified",
  "state": "valid",
  "stale": false,
  "undetermined": false,
  "undetermined_checks": [],
  "checks": [
    "capability",
    "mutability",
    "reputation",
    "sep1-domain"
  ],
  "mechanics": [
    "auth_revocable",
    "domain_unverified"
  ],
  "findings": [
    {
      "check": "capability",
      "title": "Issuer capability",
      "severity": "medium",
      "escalation": false,
      "undetermined": false,
      "reasoning": "The issuer can freeze your balance so you cannot move it (auth_revocable). ",
      "mechanics": [
        "auth_revocable"
      ],
      "evidence": [
        {
          "source": "horizon",
          "url": "https://horizon.stellar.org/assets?asset_code=USDC\u0026asset_issuer=GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
          "claim": "issuer flags: auth_required=false auth_revocable=true auth_immutable=false auth_clawback_enabled=false",
          "retrieved_at": "2026-09-28T14:16:06.786753523Z",
          "attempted": false
        }
      ]
    },
    {
      "check": "mutability",
      "title": "Issuer flag mutability",
      "severity": "clear",
      "escalation": false,
      "undetermined": false,
      "reasoning": "The issuer's flag set is not locked (auth_immutable is unset), so it can still change. The issuer can freeze an existing holder's balance (auth_revocable) today, and it may give that power up, or add another, later. Under CAP-0035 a flag added later applies only to trustlines opened after the change — it does not reach a trustline that already exists — so this verdict is correct for a trustline opened now but is not guaranteed to stay correct for one opened later. Severity is unchanged; mutability is reported, not scored.",
      "mechanics": [],
      "evidence": []
    },
    {
      "check": "sep1-domain",
      "title": "Issuer domain verification",
      "severity": "clear",
      "escalation": false,
      "undetermined": false,
      "reasoning": "The issuer advertises home_domain \"circle.com\", but its stellar.toml could not be read (sep1: fetch https://circle.com/.well-known/stellar.toml: status 404). The domain claim is unverified: anyone can set home_domain to any value, so an unreachable toml proves nothing about who issued this.",
      "mechanics": [
        "domain_unverified"
      ],
      "accountability": "unverified",
      "evidence": [
        {
          "source": "stellar.toml",
          "url": "https://circle.com/.well-known/stellar.toml",
          "claim": "not retrievable: sep1: fetch https://circle.com/.well-known/stellar.toml: status 404",
          "retrieved_at": "2026-09-28T14:16:07.164190056Z",
          "attempted": true
        }
      ]
    },
    {
      "check": "reputation",
      "title": "Curated reputation signals",
      "severity": "clear",
      "escalation": true,
      "undetermined": false,
      "reasoning": "Curated sources returned data for this issuer and none of it flags the issuer as malicious. Recorded as attributed evidence only: it does not lower the capability severity, because a named issuer holds the same power over your balance as an anonymous one.",
      "mechanics": [],
      "evidence": [
        {
          "source": "stellar.expert/directory",
          "url": "https://api.stellar.expert/explorer/directory/GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
          "claim": "listed as \"Centre\" (domain \"centre.io\", tags: anchor, issuer)",
          "retrieved_at": "2026-09-28T14:16:08.875742985Z",
          "attempted": false
        },
        {
          "source": "stellar.expert/blocked-domains",
          "url": "https://api.stellar.expert/explorer/directory/blocked-domains/circle.com",
          "claim": "domain \"circle.com\" blocked=false",
          "retrieved_at": "2026-09-28T14:16:08.726540741Z",
          "attempted": false
        }
      ]
    }
  ],
  "evidence": [
    {
      "source": "horizon",
      "url": "https://horizon.stellar.org/assets?asset_code=USDC\u0026asset_issuer=GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
      "claim": "issuer flags: auth_required=false auth_revocable=true auth_immutable=false auth_clawback_enabled=false",
      "retrieved_at": "2026-09-28T14:16:06.786753523Z",
      "attempted": false
    },
    {
      "source": "stellar.toml",
      "url": "https://circle.com/.well-known/stellar.toml",
      "claim": "not retrievable: sep1: fetch https://circle.com/.well-known/stellar.toml: status 404",
      "retrieved_at": "2026-09-28T14:16:07.164190056Z",
      "attempted": true
    },
    {
      "source": "stellar.expert/directory",
      "url": "https://api.stellar.expert/explorer/directory/GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
      "claim": "listed as \"Centre\" (domain \"centre.io\", tags: anchor, issuer)",
      "retrieved_at": "2026-09-28T14:16:08.875742985Z",
      "attempted": false
    },
    {
      "source": "stellar.expert/blocked-domains",
      "url": "https://api.stellar.expert/explorer/directory/blocked-domains/circle.com",
      "claim": "domain \"circle.com\" blocked=false",
      "retrieved_at": "2026-09-28T14:16:08.726540741Z",
      "attempted": false
    }
  ],
  "scanned_at": "2026-09-28T14:16:05.461780023Z"
}
```

### Worked example 2: Undetermined verdict due to unreachable reputation source (REPO - Captured 2026-11-23)

When an upstream dependency fails to respond (for example during network partitions or third-party outages), the affected check cannot complete. To simulate an unreachable reputation service as automated verification jobs do, set `ASSAY_STELLAREXPERT_URL` to an unreachable address (e.g. `http://127.0.0.1:1`) and scan REPO (`REPO-GA2BVQLGAG6UJDPHHTJDQAPBUYJV7D6IWIISGJI2LMQXTOKMHO36EAZR`):

```sh
ASSAY_STELLAREXPERT_URL=http://127.0.0.1:1 ./assay scan REPO-GA2BVQLGAG6UJDPHHTJDQAPBUYJV7D6IWIISGJI2LMQXTOKMHO36EAZR
```

Captured output:

```json
{
  "asset": {
    "code": "REPO",
    "issuer": "GA2BVQLGAG6UJDPHHTJDQAPBUYJV7D6IWIISGJI2LMQXTOKMHO36EAZR"
  },
  "severity": "clear",
  "base_severity": "clear",
  "escalated": false,
  "accountability": "unverified",
  "state": "unknown",
  "stale": false,
  "undetermined": true,
  "undetermined_checks": [
    "reputation"
  ],
  "checks": [
    "capability",
    "mutability",
    "reputation",
    "sep1-domain"
  ],
  "mechanics": [
    "domain_unverified"
  ],
  "findings": [
    {
      "check": "capability",
      "title": "Issuer capability",
      "severity": "clear",
      "escalation": false,
      "undetermined": false,
      "reasoning": "The issuer holds no authorization flags. It cannot freeze, confiscate, or gate this asset. ",
      "mechanics": [],
      "evidence": [
        {
          "source": "horizon",
          "url": "https://horizon.stellar.org/assets?asset_code=REPO\u0026asset_issuer=GA2BVQLGAG6UJDPHHTJDQAPBUYJV7D6IWIISGJI2LMQXTOKMHO36EAZR",
          "claim": "issuer flags: auth_required=false auth_revocable=false auth_immutable=false auth_clawback_enabled=false",
          "retrieved_at": "2026-11-23T12:29:36.665257643Z",
          "attempted": false
        }
      ]
    },
    {
      "check": "mutability",
      "title": "Issuer flag mutability",
      "severity": "clear",
      "escalation": false,
      "undetermined": false,
      "reasoning": "The issuer's flag set is not locked (auth_immutable is unset), so it can still change. The issuer holds no freeze or confiscation power today, but it may add auth_revocable or auth_clawback_enabled later. Under CAP-0035 a flag added later applies only to trustlines opened after the change — it does not reach a trustline that already exists — so this verdict is correct for a trustline opened now but is not guaranteed to stay correct for one opened later. Severity is unchanged; mutability is reported, not scored.",
      "mechanics": [],
      "evidence": []
    },
    {
      "check": "sep1-domain",
      "title": "Issuer domain verification",
      "severity": "clear",
      "escalation": false,
      "undetermined": false,
      "reasoning": "The issuer advertises home_domain \"hiddenstellar.com\", but its stellar.toml could not be read (sep1: fetch https://hiddenstellar.com/.well-known/stellar.toml: status 403). The domain claim is unverified: anyone can set home_domain to any value, so an unreachable toml proves nothing about who issued this.",
      "mechanics": [
        "domain_unverified"
      ],
      "accountability": "unverified",
      "evidence": [
        {
          "source": "stellar.toml",
          "url": "https://hiddenstellar.com/.well-known/stellar.toml",
          "claim": "not retrievable: sep1: fetch https://hiddenstellar.com/.well-known/stellar.toml: status 403",
          "retrieved_at": "2026-11-23T12:29:36.87725474Z",
          "attempted": true
        }
      ]
    },
    {
      "check": "reputation",
      "title": "Curated reputation signals",
      "severity": "clear",
      "escalation": true,
      "undetermined": true,
      "reasoning": "Reputation could not be determined: the curated directory, and the malicious-domain blocklist did not answer, and the failure is recorded above verbatim. This is not a clean result. Absence of a malicious listing is only meaningful when the list was actually read, and an asset whose only adverse signal is a curated listing would look clear here. Treat the severity below as a floor rather than an answer.",
      "mechanics": [],
      "evidence": [
        {
          "source": "stellar.expert/directory",
          "url": "http://127.0.0.1:1/explorer/directory/GA2BVQLGAG6UJDPHHTJDQAPBUYJV7D6IWIISGJI2LMQXTOKMHO36EAZR",
          "claim": "not retrievable: stellarexpert: get http://127.0.0.1:1/explorer/directory/GA2BVQLGAG6UJDPHHTJDQAPBUYJV7D6IWIISGJI2LMQXTOKMHO36EAZR: Get \"http://127.0.0.1:1/explorer/directory/GA2BVQLGAG6UJDPHHTJDQAPBUYJV7D6IWIISGJI2LMQXTOKMHO36EAZR\": dial tcp 127.0.0.1:1: connect: connection refused",
          "retrieved_at": "2026-11-23T12:29:37.764338591Z",
          "attempted": true
        },
        {
          "source": "stellar.expert/blocked-domains",
          "url": "http://127.0.0.1:1/explorer/directory/blocked-domains/hiddenstellar.com",
          "claim": "not retrievable: stellarexpert: get http://127.0.0.1:1/explorer/directory/blocked-domains/hiddenstellar.com: Get \"http://127.0.0.1:1/explorer/directory/blocked-domains/hiddenstellar.com\": dial tcp 127.0.0.1:1: connect: connection refused",
          "retrieved_at": "2026-11-23T12:29:37.763724801Z",
          "attempted": true
        }
      ]
    }
  ],
  "evidence": [
    {
      "source": "horizon",
      "url": "https://horizon.stellar.org/assets?asset_code=REPO\u0026asset_issuer=GA2BVQLGAG6UJDPHHTJDQAPBUYJV7D6IWIISGJI2LMQXTOKMHO36EAZR",
      "claim": "issuer flags: auth_required=false auth_revocable=false auth_immutable=false auth_clawback_enabled=false",
      "retrieved_at": "2026-11-23T12:29:36.665257643Z",
      "attempted": false
    },
    {
      "source": "stellar.toml",
      "url": "https://hiddenstellar.com/.well-known/stellar.toml",
      "claim": "not retrievable: sep1: fetch https://hiddenstellar.com/.well-known/stellar.toml: status 403",
      "retrieved_at": "2026-11-23T12:29:36.87725474Z",
      "attempted": true
    },
    {
      "source": "stellar.expert/directory",
      "url": "http://127.0.0.1:1/explorer/directory/GA2BVQLGAG6UJDPHHTJDQAPBUYJV7D6IWIISGJI2LMQXTOKMHO36EAZR",
      "claim": "not retrievable: stellarexpert: get http://127.0.0.1:1/explorer/directory/GA2BVQLGAG6UJDPHHTJDQAPBUYJV7D6IWIISGJI2LMQXTOKMHO36EAZR: Get \"http://127.0.0.1:1/explorer/directory/GA2BVQLGAG6UJDPHHTJDQAPBUYJV7D6IWIISGJI2LMQXTOKMHO36EAZR\": dial tcp 127.0.0.1:1: connect: connection refused",
      "retrieved_at": "2026-11-23T12:29:37.764338591Z",
      "attempted": true
    },
    {
      "source": "stellar.expert/blocked-domains",
      "url": "http://127.0.0.1:1/explorer/directory/blocked-domains/hiddenstellar.com",
      "claim": "not retrievable: stellarexpert: get http://127.0.0.1:1/explorer/directory/blocked-domains/hiddenstellar.com: Get \"http://127.0.0.1:1/explorer/directory/blocked-domains/hiddenstellar.com\": dial tcp 127.0.0.1:1: connect: connection refused",
      "retrieved_at": "2026-11-23T12:29:37.763724801Z",
      "attempted": true
    }
  ],
  "scanned_at": "2026-11-23T12:29:35.533009341Z"
}
```

### Capture the scan for replay (`-record` / `-replay`)

Live sources change; the verdict that surprised you may be impossible to reproduce tomorrow. `./assay scan -record DIR CODE-ISSUER` saves every upstream response the scan fetches into `DIR` (with a `manifest.json` index), and `./assay scan -replay DIR CODE-ISSUER` re-runs the same scan from that recording — offline and deterministically, producing the identical report and preimage digest.

```sh
./assay scan -record /tmp/usdc-2026-09-28 USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN
# ...later, after the sources have changed:
./assay scan -replay /tmp/usdc-2026-09-28 USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN
```

Rules worth knowing before you rely on it:

- **Recordings are verbatim, not cleaned up**: whatever the scan fetched is what got saved — 404s, redirects' final responses, and error pages included — because the evidence line cites the answer Assay actually read.
- **Transport errors are not recorded**: an upstream outage during recording leaves that request absent, and a replay that needs it fails loudly (`unrecorded request … refusing to reach the network`) instead of reaching the network or serving an empty answer.
- **Replay never touches the network**: the replayed transport holds no outbound connection at all. A request the scanner makes after the recording was made is an error, never a live fetch — so a recording is a faithful artifact to attach to a bug report, and a maintainer re-runs your exact scan offline.
- **A recording is not a fixture**: it captures one scan, at one instant, for one subject. `internal/fixtures` remains the curated, reviewed corpus; recordings are the raw material a bug report arrives with.

---

## Step 2: Check the attributed evidence URLs against live sources

Fetch each evidence URL cited in the report directly (using `curl` or a browser) to inspect what the live upstream source returns:

1. **Horizon asset endpoint**: Open the URL cited in the `horizon` evidence line to verify the raw flag booleans.
2. **`stellar.toml` URL**: Query the exact URL cited in the `stellar.toml` evidence line. Check the HTTP status code and response body.
3. **StellarExpert endpoints**: Check the directory and blocklist response JSONs for the issuer address and home domain.

### Worked example 1: Checking unverified domain evidence (USDC - Captured 2026-09-28)

To check why USDC scored `accountability: unverified`, query the cited `stellar.toml` evidence URL directly:

```sh
curl -i -L https://circle.com/.well-known/stellar.toml
```

Captured output:

```http
HTTP/2 301
date: Mon, 28 Sep 2026 14:16:44 GMT
content-type: text/html; charset=UTF-8
location: https://www.circle.com/.well-known/stellar.toml

HTTP/2 404
date: Mon, 28 Sep 2026 14:16:45 GMT
content-type: text/html; charset=utf-8
```

The response is an HTTP 404 error from `circle.com` (redirecting to `www.circle.com`).

### Worked example 2: Checking unreachable reputation source (REPO - Captured 2026-11-23)

To check why REPO scored `undetermined: true`, query the cited `stellar.expert` directory or blocklist URL directly:

```sh
curl -i http://127.0.0.1:1/explorer/directory/GA2BVQLGAG6UJDPHHTJDQAPBUYJV7D6IWIISGJI2LMQXTOKMHO36EAZR
```

Captured output:

```
curl: (7) Failed to connect to 127.0.0.1 port 1 after 0 ms: Couldn't connect to server
```

The response confirms the upstream reputation endpoint could not be reached, corroborating the `connect: connection refused` claim recorded in the report evidence.

---

## Step 3: Decide where the disagreement lives

Compare the live source data with Assay's report to isolate the cause:

- **The source says so (Correct-but-surprising)**: The live data source actually has the flag or state recorded in the evidence line. Assay's verdict matches what the source provided, even if that surprises the reader. The answer is **"the source says so"**, not a bug in Assay.
- **Code bug**: The live source data is valid and clean, but Assay's check misread a field, incorrectly parsed a payload, or misapplied a severity level rule.
- **Stale attestation**: The live scan produces a different verdict than what is stored on-chain because the issuer changed flags after the attestation was written. (Check `attested_at` against current time).
- **Unreachable dependency (Undetermined / Partial scan)**: An upstream dependency (such as StellarExpert) timed out, returned an error, or was unreachable. Assay records the failure verbatim as attributed evidence, marks `undetermined: true`, and sets `state: unknown`.

### Worked example 1: USDC verdict breakdown (Medium severity)

Readers are often surprised that USDC scores `severity: medium` and `accountability: unverified`:

1. **Why `severity: medium`?** Horizon reports `auth_revocable=true` for issuer `GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN`. Under Rule 1 of the [severity model](severity-model.md), severity is capability-only: `auth_revocable` allows freezing balances, which maps to `medium`. Reputation cannot lower this severity.
2. **Why `accountability: unverified`?** The evidence line cites `https://circle.com/.well-known/stellar.toml`, which returns HTTP 404. Reciprocal domain verification requires a matching `stellar.toml`. Because the file returns 404, reciprocal verification fails.

The evidence lines prove that **the source says so**. The result is correct-but-surprising, not a code bug.

### Worked example 2: REPO verdict breakdown (Undetermined vs. Critical escalation)

Undetermined is the most common surprising result in practice, and the one users most often misread:

1. **Why `severity: clear` when REPO is a known scam?** Horizon reports no capability flags (`auth_required=false`, `auth_revocable=false`, `auth_clawback_enabled=false`) for issuer `GA2BVQLGAG6UJDPHHTJDQAPBUYJV7D6IWIISGJI2LMQXTOKMHO36EAZR`. Under Rule 1 of the [severity model](severity-model.md), severity is capability-only. Because the issuer holds no freeze or clawback powers, capability severity is `clear`.
2. **Why `undetermined: true` and `state: unknown`?** The curated directory and blocklist from StellarExpert could not be reached. Because those sources did not answer, the reputation check could not conclude.
3. **Why this result surprises and misleads readers:** Under normal conditions with live sources, REPO escalates to `severity: critical` because its home domain `hiddenstellar.com` is blocklisted on StellarExpert. Because reputation is the *only* axis that can escalate, an outage in StellarExpert hides that escalation!
4. **Why Assay does not inflate severity:** Inventing a severity level Assay did not measure would be dishonest. Capability was fully readable and is reported as measured (`clear`). But the report sets `undetermined: true`, lists `undetermined_checks: ["reputation"]`, and sets `state: "unknown"` so consumers know this is a partial result.
5. **How to read it:** An undetermined verdict with `severity: clear` is **not** a clean bill of health. It means the scanner could not determine whether an escalation applies, and the reported severity must be treated as a floor rather than a complete verdict.

---

## Step 4: Look at what was hashed and what's on-chain (`./assay attestation` and `make read`)

To inspect how the report maps to an on-chain attestation:

1. **Inspect `attest()` arguments**: Run `./assay attestation -raw CODE-ISSUER` to view the `severity`, `flags` bitset, and `evidence_hash` produced by the scan.
2. **Inspect the preimage**: Run `./assay attestation -preimage CODE-ISSUER` to view the canonical text preimage hashed to produce `evidence_hash`.
3. **Read on-chain state**: Run `make read ASSET=CODE-ISSUER` to query the deployed Soroban safety registry via `get_safety`.

> [!NOTE]
> `make read ASSET=CODE-ISSUER` requires the `stellar` CLI binary installed and network access to Stellar testnet. On environments without the `stellar` CLI installed, `make read` fails with `/bin/sh: stellar: not found`.

### Worked example 1: Complete scan attestation (USDC - Captured 2026-09-28)

Run `./assay attestation -raw` for USDC:

```sh
./assay attestation -raw USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN
```

Captured output:

```
2	18	d9f2c2ce9542299ab57a2873b25fc121f3bafd0ee560afae1a5da61ae5a7dc3d
```

Run `./assay attestation -preimage` for USDC:

```sh
./assay attestation -preimage USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN
```

Captured output:

```json
{
  "asset": {
    "code": "USDC",
    "issuer": "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
  },
  "severity": 2,
  "severity_name": "medium",
  "flags": 18,
  "mechanics": [
    "auth_revocable",
    "domain_unverified"
  ],
  "checks": [
    "capability",
    "mutability",
    "reputation",
    "sep1-domain"
  ],
  "evidence_hash": "d9f2c2ce9542299ab57a2873b25fc121f3bafd0ee560afae1a5da61ae5a7dc3d",
  "scanned_at": "2026-09-28T14:17:21Z",
  "preimage": "assay-evidence-v2\nasset\tUSDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN\nseverity\t2\nbase_severity\t2\nescalated\tfalse\nmechanics\t18\naccountability\tunverified\nchecks\tcapability,mutability,reputation,sep1-domain\nevidence\thorizon\thttps://horizon.stellar.org/assets?asset_code=USDC\u0026asset_issuer=GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN\tissuer flags: auth_required=false auth_revocable=true auth_immutable=false auth_clawback_enabled=false\nevidence\tstellar.expert/blocked-domains\thttps://api.stellar.expert/explorer/directory/blocked-domains/circle.com\tdomain \"circle.com\" blocked=false\nevidence\tstellar.expert/directory\thttps://api.stellar.expert/explorer/directory/GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN\tlisted as \"Centre\" (domain \"centre.io\", tags: anchor, issuer)\nevidence\tstellar.toml\thttps://circle.com/.well-known/stellar.toml\tnot retrievable: sep1: fetch https://circle.com/.well-known/stellar.toml: status 404\n"
}
```

When run on a host with `stellar` CLI and testnet access, `make read ASSET=USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN` returns the stored record from `get_safety`:

```
USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN -> CA5ZSEJY...
severity 2, flags 18, evidence_hash d9f2c2ce...
```

### Worked example 2: Attestation refusal on undetermined report (REPO - Captured 2026-11-23)

When a scan is undetermined, `./assay attestation` refuses to output on-chain arguments or hash a preimage.

Run `./assay attestation -raw` for the undetermined REPO scan:

```sh
ASSAY_STELLAREXPERT_URL=http://127.0.0.1:1 ./assay attestation -raw REPO-GA2BVQLGAG6UJDPHHTJDQAPBUYJV7D6IWIISGJI2LMQXTOKMHO36EAZR
```

Captured output:

```
assay: attest: scan is undetermined, so there is nothing to attest: reputation could not complete
```

Run `./assay attestation -preimage` for the undetermined REPO scan:

```sh
ASSAY_STELLAREXPERT_URL=http://127.0.0.1:1 ./assay attestation -preimage REPO-GA2BVQLGAG6UJDPHHTJDQAPBUYJV7D6IWIISGJI2LMQXTOKMHO36EAZR
```

Captured output:

```
assay: attest: scan is undetermined, so there is nothing to attest: reputation could not complete
```

Under `internal/attest/attest.go`, `FromReport()` refuses any report where `Undetermined` is true (`ErrUndetermined`). This guarantees that partial or degraded scans never produce an evidence hash or reach the on-chain safety registry. Downstream, `get_safety` returns `None` for un-attested assets, and safety gates fail closed.

---

## Step 5: Decide bug vs. correct-but-surprising, and what to do next

Once you have isolated the cause:

1. **If the verdict is correct-but-surprising ("The source says so")**:
   - The scanner worked correctly. Explain to the user or contributor that Assay reports facts from live ledger and domain sources, and does not alter severity based on reputation or brand recognition.
2. **If it is a code bug**:
   - File a bug issue on GitHub describing the discrepancy between the live source evidence and Assay's verdict. Include the captured `./assay scan` JSON output and live `curl` outputs.
3. **If it is a security vulnerability (under-reporting risk)**:
   - If the bug causes Assay to report a severity *lower* than the issuer's flags justify, or fails to fail closed, **do not open a public issue**. Follow [SECURITY.md](../SECURITY.md) and report it privately.
4. **If the verdict is undetermined (`undetermined: true`)**:
   - The scan is partial because an external source failed to answer. Do not attempt to attest it on-chain (the CLI refuses to derive arguments for it). Check `undetermined_checks` and the attributed error claims in `evidence` to identify the failing source. Verify network connectivity to the service and re-scan once the dependency is restored. Never treat an undetermined report with `severity: clear` as safe or verified.
