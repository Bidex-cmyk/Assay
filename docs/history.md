# Observation history

`GET /api/v1/history` returns an asset's recorded observations, in time order,
together with the transitions derived between them. It is how a consumer reaches
the comparison in [`internal/temporal`](../internal/temporal): `scan` answers
*what is true now*, `history` answers *what did we observe, and what changed*.

```sh
curl 'http://localhost:8080/api/v1/history?asset=USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR'
```

This is a significant architectural addition — it is the first component in
Assay that retains anything — so the storage choice, the retention policy, and
the meaning of an empty history are recorded here rather than left implicit. The
comparison itself is specified in [transitions.md](transitions.md).

## Where observations come from

There is exactly one write path: **a successful `GET /api/v1/scan` records one
observation** for the asset it scanned. `history` never scans; it reads what has
been recorded.

```
GET /api/v1/scan?asset=CODE-ISSUER     →  scan, respond, and append an observation
GET /api/v1/history?asset=CODE-ISSUER  →  read the recorded observations, derive transitions
```

A scan that fails (the asset is not on the ledger, Horizon is down) records
nothing. A scan that succeeds but is `undetermined` **is** recorded, marked, and
returned — see [undetermined](#unknown--an-observation-is-incomplete).

Nothing schedules scans. History grows exactly as fast as someone scans, and
this document does not claim otherwise.

## The response

```json
{
  "asset": { "code": "USDZ", "issuer": "GAKTLPC4…U6XPR" },
  "state": "valid",
  "count": 2,
  "observations": [
    {
      "asset": { "code": "USDZ", "issuer": "GAKTLPC4…U6XPR" },
      "at": "2026-08-15T05:27:31Z",
      "mechanics": 6,
      "base_severity": "high",
      "severity": "high",
      "undetermined": false
    }
  ],
  "transitions": [],
  "limit": 100,
  "latest_at": "2026-08-15T05:27:31Z",
  "latest_age_secs": 3542400,
  "retention": 256,
  "max_assets": 512
}
```

| Field | Meaning |
| --- | --- |
| `asset` | the asset the history is for, echoed in `CODE`/`issuer` form |
| `state` | `valid`, `unknown`, or `missing` — the completeness of the history, not of any request |
| `reason` | plain-language explanation of a non-`valid` state; never omitted when the state is not `valid` |
| `count` | number of observations returned on this page, not in the whole history |
| `observations` | this page's observations, oldest first, each with its own completeness |
| `transitions` | the derived difference between each consecutive pair on the page, plus the one from the page's predecessor; empty when nothing precedes the oldest returned observation |
| `limit` | the page size actually applied |
| `next_before` | cursor for the next (older) page; absent on the page that reaches the oldest retained observation |
| `latest_at` | the most recent observation **overall**, not only on this page |
| `latest_age_secs` | its age in seconds, so a consumer can apply its own staleness policy |
| `retention` | the per-asset cap these observations were read against |
| `max_assets` | the global cap on assets the store retains (see [Bounds](#bounds-two-of-them)) |

An observation carries `mechanics` (the full bitset, as a number), `base_severity`
and `severity` (level names), and `undetermined` with `undetermined_checks`. The
full bitset is stored rather than only the capability bits, so a later question
about a bit the comparison does not handle yet can be answered without re-taking
the observation.

`transitions` entries are the same shape `internal/temporal` produces from two
observations: `added`/`removed` capability bits with names, severity before and
after, an `attribution` (`capability`, `reputation`, `both`, or `none`), and an
`accountability` movement with `from`/`to` values and its own `state`. They are
computed per request, never stored; the accountability axis is specified in
[transitions.md](transitions.md#accountability-movement).

## Semantics

The four states below are why the history view has a `state` field at all:
"nothing changed", "we have never looked", and "we could not tell" are different
answers and must never render the same. That rule is repo-wide; it was stated
first in [checks.md](checks.md) and applied to a comparison in
[transitions.md](transitions.md).

### valid — history returned in time order, each observation marked for completeness

The ordinary case: at least one observation exists and every one returned is
complete. `state` is `valid`. An empty `transitions` array is a real answer — for
a single observation it means "there is no second point to compare against", and
the observation itself is returned so the caller can see which point exists.

### missing — no history, an explicit empty result

An asset nobody has scanned returns **HTTP 200** with `state: "missing"`,
`count: 0`, `observations: []`, `transitions: []`, and a `reason` saying so. It
is never a 404 and never silence: a consumer must be able to tell "we have never
looked" from "the request failed" without interpreting a status code.

This mirrors the on-chain rule that an unattested asset returns `None` rather
than a `clear` attestation. Unknown is not safe, and an empty history is not an
error.

### unknown — an observation is incomplete

If any returned observation has `undetermined: true`, the history is `unknown`,
the observation is **returned marked rather than omitted**, `state` names the
checks that did not complete, and every transition that involves it is itself
`unknown` rather than a derived difference. Nothing may be read from what an
undetermined observation omits: a source that failed could have hidden exactly
the change being asked about.

This is the same failure that
[attestation-run.md](attestation-run.md#finding-1) fixed for a single scan, now
applied to a comparison. A history read must not silently drop the partial
observation, because a shorter history that looks complete is worse than a
marked one.

### pagination — bounded pages, walked backwards

`/api/v1/history` is paginated because the retained history is the response size
the server hits first. Two query parameters control the page:

| Parameter | Meaning |
| --- | --- |
| `limit` | page size, default **100**, maximum **256** (the per-asset retention cap) |
| `before` | exclusive time cursor: only observations **strictly older** than this RFC 3339 timestamp are returned |

A page is the latest `limit` observations not newer than `before`, so the first
request needs only `asset` and each subsequent request sends the previous
response's `next_before` back as `before`. The cursor is exclusive, which is what
makes the walk terminate: the observation named by `next_before` is returned on
the page just read and never again.

- **A transition at a page boundary is still reported.** The transition *into*
the first returned observation is derived against one predecessor from outside
the page, so `transitions` can be one longer than a page of `n` observations has
internal pairs. That predecessor is not returned as an observation, because
`count` describes the page and an unrequested entry would be one the caller
cannot page over; it is included when judging the page's `state`, because a
change derived from it is part of this response.
- **`latest_at` describes the history, not the page.** Walking backwards must
not make an asset look progressively staler than its most recent observation.
- **A page can be larger than `limit`.** Observations that share the page's
oldest timestamp are returned together, because a time cursor cannot resume
between them and splitting them would drop one from the walk. The page is
bounded by the per-asset retention cap either way.
- **An empty page is an end-of-history result, not an error** — `count: 0`,
`state: "valid"`, and no `next_before`. Reaching the end of what is retained is
not the same as having no history at all, which is `state: "missing"`.
- **Invalid parameters are refused with `400`.** That covers a non-numeric or
zero `limit`, a `limit` above 256, and a `before` that is not an RFC 3339
timestamp. Unlike the exposure endpoint, the limit is **not clamped**: a caller
walking a cursor has to know exactly how its request was interpreted, and a
silently clamped page would make the cursor it computes wrong.

### stale — the age is reported, the policy is yours

`latest_at` and `latest_age_secs` describe the most recent observation. Assay
does **not** declare a history stale and has no freshness threshold: a deposit
gate and a large settlement have different tolerances, so the consumer decides,
exactly as `max_age_secs` works on-chain. The API reports the age; it does not
act on it.

## Storage decision

**Decision: append-only JSON Lines, written with the standard library. No new
third-party dependency.**

The registry's whole threat model is that third-party trust is taken on only by
an explicit decision. Keeping a few hundred small records per asset does not
justify inheriting a database's supply chain, and `encoding/json` and `os` are
already part of the toolchain. A dependency here would need a maintainer
decision, and this design does not ask for one. (The merge gate holds any change
to `go.mod`/`go.sum` for review for the same reason.)

The store lives in [`internal/history`](../internal/history):

- **In-memory by default.** `api.NewServer` uses an in-memory store, so a
  bare `assay serve` keeps history for the life of the process and loses it on
  restart. That is deliberate: losing history is honest, whereas writing to a
  path nobody configured would be a surprise.
- **File-backed on request.** `assay serve -history /var/lib/assay/history.jsonl`
  loads the log at startup and rewrites it on every append. The rewrite is whole
  and atomic (a temporary file renamed over the target), so after each append
  the file is exactly the retained set and a crash cannot leave a half-written
  observation. The log is small and written at human rates; a full rewrite is
   simpler and more obviously correct than an append log with periodic
   compaction, and it means a restart cannot resurrect an evicted observation.
   After the rename the **containing directory is synced**, so the rename itself
   survives a power loss on filesystems where the directory entry is not durable
   by the time the file's contents are. A sync error is reported as an append
   failure, not ignored; the only errors ignored are `EINVAL`/`ENOTSUP`, which
   mean the filesystem does not support directory sync at all. On platforms
   that cannot open a directory for syncing, the step is a documented no-op
   (see [Durability and writers](#durability-and-writers)).
- **The on-disk record is versioned and separate from the wire shape.**
  Severity is stored as the number the model is built from, not the level name
  the API displays, and every record carries a `v` field. A future change to
   either shape cannot be read as this one. `accountability` is persisted so a
   reopened log can still derive an accountability movement; older records
   without the field load with it empty rather than failing to open.

### Durability and writers

Two properties of a file-backed store are worth stating explicitly because
neither is visible from the JSON on disk:

- **Rename durability.** The temporary file is written, closed, renamed over
  the log, and then the containing directory is synced. File contents and the
  directory entry are separate durable facts; syncing only the file would leave
  a crash able to undo the rename and lose the whole append. An unsupported
  directory sync is ignored only where the platform or filesystem cannot do it,
  never when it fails for another reason.
- **One writer per log.** `history.Open` takes an exclusive, non-blocking
  advisory lock on a **sidecar `PATH.lock` file** and keeps it for the store's
  lifetime. A second `assay serve -history PATH` refuses to start with
  `ErrLocked` ("already in use by another process") instead of silently
  overwriting the first process's observations. The lock is on a sidecar because
  each append replaces the log by rename — locking the log inode would not
  protect the next write. `Store.Close` releases the lock; process exit does too
  through the OS. **Fallback:** on platforms without the `flock` syscall the
  lock is a no-op and the single-writer guarantee does not exist — run only one
  writer per history path there. Both behaviors are implemented in
  `internal/history/platform_*.go` and tested in `internal/history/store_test.go`.

### Bounds: two of them

**Retention is a count, not a time window, and there are two bounds.** The
per-asset cap is `history.DefaultRetention` — **256 observations per asset**,
changed with `assay serve -history-retention N` — and the global cap is
`history.DefaultMaxAssets` — **512 assets**. When either is
exceeded, the oldest is evicted first: the oldest *observation* of that asset, or
the asset whose most recent observation is oldest.

Both bounds are needed. A per-asset cap alone bounds nothing in aggregate: every
distinct asset scanned through the public API adds up to 256 records, and the
whole file is rewritten on every append, so an instance could be driven to an
arbitrarily large file and O(n) write cost merely by scanning many assets. With
both bounds the log can never exceed `512 × 256` records, whatever an outside
caller scans, and the write cost of an append is bounded by that same number.

The global bound evicts **whole assets, least-recently-observed-first**, rather
than trimming every asset's history. The asset whose newest observation is oldest
is the one a consumer is least likely to ask about, an asset that is still being
scanned is never the one a burst of new assets drops, and no asset is ever left
with a partial history that would read as complete. Ties are broken by asset key,
so eviction cannot depend on map iteration order.

The response reports `retention` and `max_assets` for exactly this reason: a
consumer can see which caps the answers were read against and must read them
rather than assuming completeness. A consumer that sees exactly `retention`
observations on an asset should read the history as possibly truncated at the
oldest end. One consequence is stated rather than hidden: **an evicted asset's
history reads as `missing`**, the same as an asset that was never scanned. On a
deployment that has reached `max_assets`, `missing` therefore means "not retained"
as well as "never observed"; an asset that must stay pageable should not be left
unscanned long enough to age out.

Transitions are recomputed from retained observations on every request, so
evicting an old observation can make an old transition unavailable. That is the
honest consequence of a bounded history, and it is why the pair is returned
alongside each difference.

## What this does not do

- **No backfill.** There is no history for scans that happened before the store
  existed, and no way to import one.
- **No CLI surface change.** The `assay history` subcommand is a separate,
  report-derived view ([cli.md](cli.md)); this document describes the HTTP
  endpoint. The issue that added the endpoint explicitly scoped the CLI out.
- **No deletion API.** Retention is the only removal, and it is oldest-first.

## Scheduled observation

`assay serve` can now run scheduled scans of a configured asset list and append
observations to history automatically:

```sh
assay serve -observe /path/to/assets.txt -observe-interval 6h
```

- `-observe FILE` — path to a text file with one `CODE-ISSUER` asset per line.
  Empty lines and lines starting with `#` are ignored.
- `-observe-interval DURATION` — interval between scans (default `6h`).

Each scheduled scan uses the same scan path as `/api/v1/scan`, records an
observation in the history store, and respects upstream rate limits. Observations
from scheduled scans are marked as determined by the scan result (undetermined
scans are recorded as such).

The scheduler runs the first scan immediately on startup, then repeats at the
configured interval. It stops cleanly when the server shuts down.

## Tests

The endpoint's four required cases — empty history, a single observation,
multiple observations with a transition, and an observation that is
undetermined — are covered hermetically, with no network, along with pagination
(`TestHistoryPaginationWalksTheHistory`, including the page-boundary transition)
and the global bound:

```sh
go test ./internal/api/ -run History -v
go test ./internal/history/ -v
```

## Verification

```sh
go test -race ./...
```

## Related

- [transitions.md](transitions.md) — what a transition is and why it is computed
  rather than stored.
- [checks.md](checks.md) — the rule that "we could not check" and "this is fine"
  must never render the same.
- [cli.md](cli.md) — the `serve` flag that enables persistence.
