---
PLAN: "feat: DownloadWithin — a downloader whose timeout the caller chooses"
EXECUTOR: jules
REVIEWER: none
---

> This plan is dispatched via the CodeJob workflow. See skill: agents-workflow.

# Plan — one timeout does not fit both callers

## Why

`DefaultDownload` (`download.go:17`) hardcodes a 60-second HTTP timeout, and it
is used for two jobs with opposite requirements:

- **`ResolveLatestVersion`** — one small JSON GET against
  `api.github.com/repos/<owner>/<repo>/releases/latest`. Its caller
  (`webtyp.com/app`) runs it **synchronously on startup, before the dev daemon
  is launched**, to decide whether a newer binary exists.
- **`applyRelease`** — downloading a ~30 MB binary and its checksum file. Sixty
  seconds is the right order of magnitude here, and may even be tight on a slow
  link.

Today a developer with no network, or behind a black-holing firewall, waits up
to a full minute staring at nothing before `webtyp dev` does anything at all.
That is currently masked by a once-per-24h throttle in `webtyp.com/app`, which
is being **deleted** (see
`https://github.com/webtyp/app/blob/main/docs/PLAN_STAGE_4_SELFUPDATE.md`, §4.3:
the check should simply happen when the tool opens, and a stored timestamp is
complexity that buys nothing). Once that throttle is gone, the 60 seconds are
paid on **every** launch instead of once a day, so this package has to let the
version check bound its own wait.

The fix belongs here, not at the call site: this package owns how an HTTP
request to GitHub is made — the `Accept` header, the `GITHUB_TOKEN`/`GH_TOKEN`
fallback, the status check. A caller that wanted a different timeout would have
to duplicate all of it, and then the auth behaviour would exist in two places
and drift.

## Design gate

This adds one exported function, so per skill **api-design**:

### 1. Prior art

- **`net/http.Client`** — the timeout is a field on the client the caller
  constructs; the stdlib never hardcodes one. **We differ** by not exposing a
  `*http.Client`: callers here want a `func(string) ([]byte, error)`, which is
  what `ResolveLatestVersion` and `applyRelease` already take, and handing them
  a client would push request construction back out to them.
- **`google/go-github`** — takes an `*http.Client` in its constructor, so the
  caller owns transport policy entirely. **We differ** for the same reason: this
  package is four functions, not a client library, and its whole value is that
  the GitHub-specific request details live in one place.
- **`hashicorp/go-getter`** — options are applied as variadic functional
  options on each call. **We differ** because there is exactly one knob, and a
  variadic option API for one knob is ceremony; if a second knob ever appears,
  `DownloadWithin` is the natural place to grow one and the signature change is
  contained.

### 2. Novice-name test

`update.DownloadWithin(4 * time.Second)` reads as "download, within four
seconds", and returns the same kind of function `DefaultDownload` already is.
The call site becomes
`update.ResolveLatestVersion(src, update.DownloadWithin(versionCheckTimeout))`,
which a junior reads correctly without opening this package.

Rejected: `NewDownloader` (says nothing about what is configurable),
`DownloadWithTimeout` (accurate but `Within` already means "with a limit of",
and the parameter type says it is a duration).

### 3. Complexity ledger

```
Concepts a developer must learn   +1 / −0   (one function, whose body is the
                                             existing one with the constant
                                             replaced by a parameter)
Files touched to do X              +0       (download.go only)
Lines at the call site             +0       (a caller that wants the default
                                             keeps calling DefaultDownload)
Ways to do the same thing          +0       (DefaultDownload becomes a
                                             one-line call to DownloadWithin;
                                             there is exactly ONE implementation)
```

The last row stays at zero because `DefaultDownload` is **reimplemented in terms
of** `DownloadWithin`, not duplicated beside it.

### 4. Where it belongs

`update` owns "how this tool talks to GitHub releases". The timeout is part of
that conversation, and the only thing about it that legitimately varies by
caller. It is not a second concern.

### 5. What this deletes

The hardcoded `60 * time.Second` literal inside `DefaultDownload`'s body, and
with it the assumption that one timeout serves both a metadata lookup and a
30 MB download.

## Anti-footguns

1. **This repo is backend tooling, not WASM.** `net/http`, `os`, `io`, `fmt`,
   `time` are legitimate here. Do **NOT** "fix" them to `webtyp.com/fmt`
   equivalents.
2. **`DefaultDownload`'s behaviour must not change at all** — same headers, same
   token fallback, same status check, same 60-second budget. Existing callers
   and tests must keep passing untouched. This plan is purely additive.
3. **Do not add a `context.Context` parameter.** The caller signature
   `func(string) ([]byte, error)` is fixed by `ResolveLatestVersion` and
   `applyRelease`; changing it is a much larger, separate change and is not
   wanted here.

## The change — `download.go`

```go
const (
	EnvGitHubToken = "GITHUB_TOKEN"
	EnvGHToken     = "GH_TOKEN"

	// DefaultTimeout is the budget DefaultDownload uses. It is sized for
	// fetching a release binary, not for a metadata lookup — a caller doing
	// the latter on a latency-sensitive path should use DownloadWithin.
	DefaultTimeout = 60 * time.Second
)

// DownloadWithin returns a downloader that gives up after timeout. Everything
// else — the Accept header, the GITHUB_TOKEN/GH_TOKEN fallback, the status
// check — is identical to DefaultDownload, which is this function with
// DefaultTimeout.
//
// It exists because the two things this package downloads have opposite needs:
// a release binary is tens of megabytes and deserves a minute, while resolving
// the latest version tag is one small JSON response on a path where a user is
// waiting for a tool to start. Sixty seconds of silence before a CLI does
// anything is a worse failure than not knowing whether an update exists.
func DownloadWithin(timeout time.Duration) func(string) ([]byte, error) {
	return func(url string) ([]byte, error) {
		client := &http.Client{Timeout: timeout}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")

		token := os.Getenv(EnvGitHubToken)
		if token == "" {
			token = os.Getenv(EnvGHToken)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("bad status: %s", resp.Status)
		}

		return io.ReadAll(resp.Body)
	}
}

// DefaultDownload was MOVED verbatim from webtyp/installer (mode_binary.go).
func DefaultDownload(url string) ([]byte, error) {
	return DownloadWithin(DefaultTimeout)(url)
}
```

`DefaultDownload`'s old body is **moved**, not copied: after this change the
request-building code exists exactly once.

## Tests — `download_test.go` (new file, or extend the existing one if present)

Use `net/http/httptest`; no real network.

1. **A server that never responds trips the timeout.** Start an `httptest`
   server whose handler blocks on a channel the test closes in a `defer`. Call
   `DownloadWithin(50 * time.Millisecond)` against it, assert a non-nil error
   and that the call returned in well under a second.
2. **A fast server succeeds and the body comes back whole.** Assert the returned
   bytes equal what the handler wrote.
3. **The `Accept` header and the token are still sent.** Handler records
   `r.Header`; with `t.Setenv("GITHUB_TOKEN", "abc")`, assert
   `Accept: application/vnd.github+json` and `Authorization: Bearer abc`.
4. **`GH_TOKEN` is the fallback.** With `GITHUB_TOKEN` unset (`t.Setenv` to "")
   and `GH_TOKEN` set, assert the header carries the `GH_TOKEN` value.
5. **Non-200 is an error naming the status.** Handler returns 404; assert the
   error message contains `404`.
6. **`DefaultDownload` still behaves identically** — run test 3 through
   `DefaultDownload` instead and assert the same headers.

## Acceptance

- `go test ./...` passes.
- `grep -n "60 \* time.Second" download.go` → **no match** (it is now
  `DefaultTimeout`, declared once).
- `grep -c "http.NewRequest" download.go` → **1** — the request is built in one
  place, not two.
- `go doc ./... | grep DownloadWithin` → the function is exported and documented.

## Stages

| Stage | Files | Done when |
|---|---|---|
| 1 | `download.go` | `DefaultTimeout` declared; `DownloadWithin` added with the moved body; `DefaultDownload` delegates to it |
| 2 | `download_test.go` | all six tests above pass |

## Consumer — not this repo's work

`webtyp.com/app` switches its version check to
`update.DownloadWithin(versionCheckTimeout)` as part of its own Stage 4 §4.3.
Do not edit that repo from here, and do not wait for it: this plan is additive
and breaks nothing, so it can ship on its own.
