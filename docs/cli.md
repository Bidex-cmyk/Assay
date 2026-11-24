# The CLI

`assay` is one binary with several subcommands. Commands that emit a document
(`scan`, `attestation`, `history`) print human-readable JSON by default, and
scripts can ask for a tab-separated `-raw` form where one exists. `verify` and
`diff` print a human-readable verdict by default and take `-json` for scripting.

```
usage:
  assay scan CODE-ISSUER          classify one asset and print the report as JSON
  assay attestation CODE-ISSUER   print the on-chain attest() arguments for one asset
  assay verify [-json] [-max-age SECS] [-differential [-rpc URL]]
               [-registry-rpc URL] [-contract C...] [-network NETWORK] CODE-ISSUER
                                  compare a live scan with the on-chain attestation
                                  (with -differential, also re-read issuer flags via RPC)
  assay verify -bundle IN [-json]
                                  verify an offline bundle without a network
  assay diff [-json] A.json B.json
                                  compare two saved reports and print what changed
  assay history [-guarantee] [-raw] [-server URL] CODE-ISSUER
                                  print the asset's observation history
  assay registry-history [-registry-rpc URL] [-rpc URL] [-contract C...] [-network NETWORK] [-json] ASSET
                                  print the registry's attest/revoke events for an asset
                                  (CODE-ISSUER or SAC address), bounded by RPC event retention
  assay verify-preimage [-version VERSION] HASH PREIMAGE
                                  compare a stored hash with canonical preimage bytes
  assay checks                    print every check's ID and description
  assay serve [-addr] [-history PATH] [-history-retention N] [-observe FILE] [-observe-interval DURATION]
                                  serve the HTTP API and UI
  assay version                   print scanner identity, preimage encodings
                                  and build (VCS, Go) information

Commands that scan also accept:
  -cache-directory-ttl D   reuse a curated directory answer for D (0 disables)
  -cache-blocklist-ttl D   reuse a blocklist answer for D (0 disables)
  -no-cache                re-fetch curated sources and asset lists on every scan

Commands that consume SEP-0042 asset lists (scan, attestation, history, serve)
also accept:
  -asset-lists URL[,URL...]
                           SEP-0042 Stellar Asset Lists to consume
                           (repeatable). No list is used by default.

The scan command additionally accepts:
  -record DIR             save every upstream response into DIR with a
                          manifest, for later -replay
  -replay DIR             serve every upstream response from a recording;
                          an unrecorded request fails loudly instead of
                          reaching the network

The attestation command additionally accepts:
  -preimage-version V     render the preimage under encoding V (v1, v2, v3,
                          v4 or assay-evidence-vN) instead of the one the
                          report binds, so an already-recorded hash can be
                          reproduced from a fresh scan
  -bundle OUT             also write an offline verification bundle (raw
                          source bytes, report, preimage, digest) to OUT

The history command additionally accepts:
  -server URL             fetch history from a running assay server instead of
                          computing from a local scan (e.g. http://localhost:8080)

The verify command additionally accepts:
  -registry-rpc URL       Soroban RPC endpoint for the registry (env ASSAY_RPC_URL)
  -contract ID            registry contract id (env ASSAY_CONTRACT_ID)
  -network NAME           network used to derive the SAC id (env ASSAY_NETWORK)

The serve command additionally accepts:
  -history-retention N    observations kept per asset (default 256)
  -observe FILE           path to asset list file for scheduled observation
  -observe-interval DURATION
                          interval between scheduled scans (default 6h)
  -trusted-proxies CIDR[,CIDR...]
                          trusted reverse proxy CIDRs for rate limiting
```

Commands that consume SEP-0042 asset lists (`scan`, `attestation`, `history`,
`serve`) also accept:

- `-asset-lists URL[,URL...]` — SEP-0042 Stellar Asset Lists to consume, given
  as a comma-separated list or repeated. **No list is used by default**: nothing
  is hardcoded as authoritative, and no report changes unless you opt in. See
  [asset-lists.md](asset-lists.md).

## Asset identifiers

Every command that takes an asset accepts the same three spellings of it:

| Spelling | Example |
| --- | --- |
| `CODE-ISSUER` (canonical) | `USDC-GA5Z…` |
| `CODE:ISSUER`, as most Stellar tools print it | `USDC:GA5Z…` |
| a stellar.expert asset URL, paste-able from the browser | `https://stellar.expert/explorer/public/asset/USDC-GA5Z…` |

They are normalised on input, and the canonical `CODE-ISSUER` form is what
every output — report, evidence lines, preimage — prints, so the bytes
`evidence_hash` commits to are identical whichever form you pasted. The URL's
`<network>` segment is not checked: which ledger the scan reads is settled by
the scanner's network binding (#41), not by the address bar.

## assay scan

Scans one asset and prints the full report: the findings, the reasoning behind
each, and the evidence every conclusion is attributed to.

```
./assay scan CODE-ISSUER              # the findings and reasoning
```

The network's native asset is not scannable: it has no issuer account, so
there are no authorization flags to read. `assay scan native` (or `XLM`, any
case) recognises the input and refuses it with an explicit explanation rather
than a parse error, prints nothing to stdout, and exits 2:

```
assay: native asset has no issuer and no authorization flags: "XLM" cannot be scanned or attested
```

Every command that takes an asset — `scan`, `attestation`, `history`,
`verify` — refuses it the same way, so the native asset can never be scanned
or attested from the CLI. A credit asset whose code merely happens to be XLM
(`XLM-G…`) is scanned as the ordinary asset it is.

## assay attestation

Derives the arguments of an on-chain `attest()` call from a live scan. It
deliberately does not submit anything: signing belongs to whoever holds the
attester key, and keeping derivation separate from submission means the
numbers going on-chain can be inspected before a key ever touches them.

```
./assay attestation CODE-ISSUER       # severity, flags, evidence_hash
./assay attestation -preimage CODE-ISSUER   # + the bytes the hash commits to
./assay attestation -raw CODE-ISSUER  # just `SEVERITY<TAB>FLAGS<TAB>HASH`
```

`-preimage-version vN` renders the report under a historical encoding instead
of the one it binds, and accepts `v1`, `v2`, `v3`, `v4` or the full
`assay-evidence-vN` line. It can withhold bindings the scan carries (a live
scan is `v4`), but never add one: asking for a version that binds something
the report lacks is refused.

```
./assay attestation -preimage -preimage-version v1 CODE-ISSUER
```

This is how an attestation already on chain is reproduced: the recorded
`evidence_hash` was hashed over the bytes of its recorded version, so a
verifier must re-render those bytes rather than compare against whatever the
current scanner emits. The version the report itself binds is unchanged; only
the rendering is. An unknown version is refused before anything is printed.

With `-raw` and no `-preimage-version`, the output is unchanged: three fields,
`SEVERITY<TAB>FLAGS<TAB>HASH`. With `-preimage-version`, a fourth field is
appended — the hash the report renders under the version the current binary
would pick — so a caller can tell evidence drift from metadata drift:

```
SEVERITY<TAB>FLAGS<TAB>HASH(version)<TAB>HASH(current)
```

`scripts/reproducibility.sh` is the reference consumer: when the first hash
does not match the recorded one but the second does, the evidence is unchanged
and it reports `ENCODING` rather than a misleading `MISMATCH`.

`-bundle OUT` writes an offline verification bundle while deriving the
attestation: the exact response bytes the scan read, the report, the preimage,
the digest and the scanner identity. The scan is recorded into a private
temporary directory first, so a failed scan leaves no half-written archive.

```
./assay attestation -bundle attestation.tar.gz CODE-ISSUER
./assay verify -bundle attestation.tar.gz
```

See [offline-bundle.md](offline-bundle.md) for the archive layout and the
redistribution rules.

## assay verify

Checks one asset end to end: re-scans it, recomputes the evidence hash, reads
the on-chain attestation through Soroban RPC simulation without external dependencies, and reports whether the two
agree. It replaces two commands and a human comparing hex by eye.

```
./assay verify CODE-ISSUER
./assay verify -json CODE-ISSUER
./assay verify -max-age 3600 CODE-ISSUER   # also treat an old attestation as stale
./assay verify -differential CODE-ISSUER   # also re-read issuer flags via Soroban RPC
./assay verify -differential -rpc https://rpc.example CODE-ISSUER
./assay verify -registry-rpc https://rpc.example -contract C... -network pubnet CODE-ISSUER
```

Flags:

- `-max-age SECS` — treat an attestation older than this many seconds as stale.
  `0` (the default) disables the age check; freshness is the caller's policy.
- `-json` — print the full verdict as JSON for scripting.
- `-differential` — opt in to a second ledger read: re-derive the issuer's
  authorization flags through Soroban RPC and compare them with the flags the
  scan used. It does not change the hash comparison; it runs alongside it.
- `-rpc URL` — Soroban RPC endpoint for `-differential` (default: SDF testnet;
  distinct from `-registry-rpc`). A pubnet run must name an endpoint the caller trusts.
- `-registry-rpc URL` — Soroban RPC endpoint for the registry (default: SDF testnet,
  env `ASSAY_RPC_URL`).
- `-contract ID` — registry contract ID (default: live deployment, env `ASSAY_CONTRACT_ID`).
- `-network NAME` — network used to derive the SAC ID (default: `testnet`, env `ASSAY_NETWORK`).

The contract and network default to `ASSAY_CONTRACT_ID` and `ASSAY_NETWORK` (or the
compiled defaults: live testnet registry and testnet). The verdict classes are deliberately
distinct, and each has its own exit code:

| Outcome | Meaning | Exit |
| --- | --- | --- |
| `agree` | the scan, recomputed hash and chain match | 0 |
| `mismatch` | one or more of severity, flags or `evidence_hash` differs | 1 |
| `stale` | they match, but the attestation is older than `-max-age` | 2 |
| `absent` | no attestation exists on chain for this asset | 3 |
| `unverifiable` | the scan is undetermined or unevaluated, so no verdict is possible | 4 |

An undetermined scan never reports agreement. A mismatch names the differing
fields and prints both sides.

With `-differential`, the verdict also carries a `differential` object in JSON
and a `differential:` section in text. Its state is one of the four defined in
[differential.md](differential.md):

| Differential state | Meaning | Verification exit |
| --- | --- | --- |
| `agreement` | both ledger routes read the same flags | unchanged (0 when the hash outcome is `agree`) |
| `disagreement` | both answered with different flags | `1`, even when the hash comparison agreed |
| `inconclusive_one_side` | exactly one route produced a reading | unchanged; not agreement, but not a disagreement |
| `inconclusive_both_sides` | neither route produced a reading | unchanged; nothing was verified |

A disagreement is the one differential state that fails verification: two
independent readings of the same fact disagreeing needs human investigation,
and neither side is chosen automatically. An inconclusive differential read is
reported as such and never rendered as agreement.

### Offline bundles

`-bundle IN` verifies an archive written by `assay attestation -bundle`. It
touches no network and runs no scan: it recomputes the digest from the archived
preimage and checks every file the manifest binds.

```
./assay verify -bundle attestation.tar.gz
./assay verify -bundle attestation.tar.gz -json
```

A valid bundle exits 0, a tampered or incomplete one exits 1, and an archive
that cannot be opened exits 4 — a broken file is not a mismatch. `-max-age`
cannot be combined with `-bundle`, because the archive records the report but
not when the attestation was written. `-differential` is likewise refused with
`-bundle`: an archive has no live scan to re-read flags from. The format, the
files it contains and the redistribution terms are in
[offline-bundle.md](offline-bundle.md).

## assay diff

Compares two saved reports (`assay scan` output) and prints what moved:
capability bits added and removed, severity movement, accountability movement,
and evidence-only changes. It runs the same detectors the history API uses, so
"what changed" has one definition across the CLI and HTTP surfaces.

```
./assay scan CODE-ISSUER > before.json
# ... time passes ...
./assay scan CODE-ISSUER > after.json
./assay diff before.json after.json
./assay diff -json before.json after.json
```

Both documents must carry the same `schema_version` and describe the same
asset. An undetermined side is reported as undetermined, not as "no change";
[transitions.md](transitions.md) defines each state. The command validates the
saved files but does not re-derive either verdict.

## assay history

Prints an asset's observation history: one line per recorded observation, in
time order, derived from the report's evidence entries. Where `scan` answers
"what is true now", `history` answers "what did we observe, and when" — the
view an auditor needs when an asset's state changed and someone wants to know
whether it was ever different.

Each entry carries the asset, the report's severity at scan time, the
**transition** — what the issuer was observed doing, reduced to a term
(`malicious`, `listed as`, `blocked`, or `not retrievable`) — the observation's
reason verbatim, and the time it was retrieved. These labels come from the
check, evidence source, fetch status, and structured outcome. Claim text is
shown as the reason only; it does not determine the label.

An observation that does not reduce to a known transition prints as
`unknown`. The history view deliberately does not re-derive the verdict; it
reports what each observation said.

```
./assay history CODE-ISSUER           # the observations as JSON
./assay history -raw CODE-ISSUER      # `ASSET<TAB>SEVERITY<TAB>TRANSITION<TAB>REASON`
```

Flags:

- `-raw` — print the history tab-separated instead of as JSON, for scripting.
- `-guarantee` — exit non-zero when the asset has no observations, so a script
  can distinguish "no history" from "history ran fine" without parsing output.

Semantics:

- **valid state** — the observations print in time order.
- **missing state** — a clear message (`no observations for ASSET`), and exit
  0 unless `-guarantee` was given.
- **unknown state** — an observation without a recognized structured outcome
  prints with transition `unknown` rather than being dropped.

## assay verify-preimage

Compares a stored SHA-256 evidence hash with canonical preimage bytes. `PREIMAGE`
is a file path, or `-` to read the bytes from standard input. `-version` names
the encoding version expected by the stored hash; without it, the verifier
checks the current bytes and then tests the supported v1-v4 representation
changes. This comparison only downgrades a supplied preimage, since newer
encodings bind metadata that older versions do not contain.

```
./assay verify-preimage HASH preimage.txt
./assay verify-preimage -version assay-evidence-v1 HASH preimage.txt
./assay attestation -preimage CODE-ISSUER | jq -r .preimage | ./assay verify-preimage HASH -
```

The command prints one token and uses distinct exit codes for verification
outcomes:

- `MATCH` — exit 0; the preimage hashes to the stored hash.
- `MISMATCH` — exit 1; neither the supplied encoding nor a supported
  version-only recomputation matches.
- `ENCODING_DIFFERS` — exit 2; the same evidence matches after recomputing
  with an older supported encoding version.
- Invalid arguments, unsupported versions, or unreadable input — exit 3.

## assay checks

Prints every check's ID and `Describe()` text from the default engine, matching
the check set bound into v2/v3/v4 preimages.

```
./assay checks
```

Output is tab-separated (`ID<TAB>DESCRIPTION`), one check per line:

```
capability	Maps the issuer's authorization flags to a capability severity: what the issuer can do to a holder's balance. Says nothing about who the issuer is or whether they are likely to use the power.
mutability	Reports whether the issuer's flag set can still change: locked with no dangerous flags (a durable safety property), locked with freeze or clawback (the power is permanent), or unlocked (the issuer may add freeze or confiscation later, which under CAP-0035 would not reach existing trustlines but would apply to ones opened after the change). Never sets severity: auth_immutable is not a power over holders.
reputation	Consumes StellarExpert's curated address directory and malicious-domain blocklist, plus any configured SEP-0042 asset list, as attributed evidence. Escalates to critical on a confirmed listing; never lowers severity, and says nothing about an asset that a curated list does not contain.
sep1-domain	Checks whether the issuer's advertised home_domain publishes a stellar.toml that claims this exact asset. Establishes accountability, not safety: it never raises or lowers severity.
```

## assay serve

Serves the HTTP API and UI. The API exposes the same reports the CLI prints;
see `docs/integrating.md` for what a consumer reads out of it, and
[history.md](history.md) for the observation history endpoint.

```
./assay serve -addr :8080
./assay serve -addr :8080 -history /var/lib/assay/history.jsonl
./assay serve -addr :8080 -history /var/lib/assay/history.jsonl -history-retention 1024
./assay serve -addr :8080 -scan-rate 10 -scan-burst 20
```

Each successful `GET /api/v1/scan` records an observation, and
`GET /api/v1/history?asset=CODE-ISSUER` returns them in time order with the
derived transitions. `-history` points that store at an append-only JSON Lines
log so it survives a restart; without it, history is in memory and lost when the
process exits. `-history-retention N` sets how many observations are kept per
asset, for both the in-memory and the file-backed store; the default is 256 and
`GET /api/v1/history` reports the configured value as `retention`. The full
policy is in [history.md](history.md).

**Rate limiting.** `GET /api/v1/exposure` is always rate-limited (default: 5
requests burst, 1 per second per client address) because one request fans out
to a full scan per asset. `GET /api/v1/scan` is **not rate-limited by default**
so local and development use works without configuration. For public deployments
set `-scan-rate` and `-scan-burst` to protect the shared Horizon and
StellarExpert upstreams from being hammered under Assay's User-Agent:

```
-scan-burst N  initial burst of N scan requests allowed per client address
               (default: 0, off)
-scan-rate F   token-bucket refill rate in requests/second per client address
               (requires -scan-burst; default: 0, off)
```

A refused scan returns `429 Too Many Requests` with a `Retry-After` header
giving the number of seconds to wait.

Behind a reverse proxy or load balancer, configure `-trusted-proxies CIDR[,CIDR...]`
so rate limiters key on the real client IP from `X-Forwarded-For` rather than
the proxy peer. Untrusted peers cannot spoof their bucket via headers. See [api.md](api.md).

## assay version

Prints the scanner identity a verifier needs before comparing hashes: which
scanner produces this binary's reports, which preimage encoding it binds, and
how the binary was built. `assay -version` and `assay --version` print the
same thing.

```
./assay version
```

One fact per line:

```
scanner:       devel
preimage:      assay-evidence-v4
encodings:     assay-evidence-v1 assay-evidence-v2 assay-evidence-v3 assay-evidence-v4
module:        github.com/use-assay/assay devel
go:            go1.26.9
vcs.revision:  7f3c1ab4e0d9c8b2a6f5d4c3b2a1908f7e6d5c4b
vcs.modified:  false
```

- `scanner` is `attest.ScannerIdentity` — the same identity the v4 preimage's
  `scanner` line binds, so the printed value and the hashed value cannot
  disagree for the same binary. `devel` means the binary was built from a
  checkout without a release tag (see [verifying.md](verifying.md)).
- `preimage` is the newest preimage encoding this build writes. `encodings`
  lists every encoding the build still understands, oldest first, so a
  verifier knows whether the binary can reproduce an already-recorded
  `evidence_hash` under its original encoding.
- `module`, `module version`, `go`, `vcs.revision` and `vcs.modified` come
  from the build info the Go toolchain stamps into the binary — the same
  facts `go version -m` prints, reduced to the ones a verifier needs. The VCS
  fields read `unknown` when the binary carries no VCS stamp (for example a
  release built with `-buildvcs=false`).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | Generic failure: the command ran but could not deliver a result. |
| 2 | Usage error: the command or its arguments cannot be used as given — an unknown command, a missing or malformed `CODE-ISSUER`, or an identifier naming the native asset, which is never scannable. |
| 3 | Not found: the asset or attestation does not exist on the ledger. |
| 4 | Upstream unavailable: a source the scan depends on could not be reached. |
| 5 | Undetermined: the scan ran, but a source outage or an inconsistency left no verdict to report. |

The native-asset refusal is deliberately a usage code rather than a generic
failure: it is answered from the ledger's own rules before any fetch, so it is
permanent and no retry will change it — a script can distinguish "this
identifier will never scan" from a transient failure without parsing stderr.
The same input is answered by the HTTP API as `400 Bad Request` with the same
message; see [api.md](api.md).
