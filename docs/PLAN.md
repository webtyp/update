---
PLAN: "feat: signed release manifest (image + digest) for self-hosted updates"
EXECUTOR: jules
REVIEWER: none
---

> Read AGENTS.md at the repo root before any change.

# Signed release manifest

## Context

A self-hosted server (Docker Compose) updates an app by pulling a new container image. Before it pulls, it must know
that **this exact image** was published by the app's owner: a tag such as `:v0.0.78` can be moved, so the trust anchor is
the image **digest**. The publisher (`webtyp/gorelease`, a later plan) uploads two assets to the GitHub Release:

- `manifest.txt` — three lines naming the version, the image and its digest;
- `manifest.sig` — the signature of `manifest.txt`'s exact bytes.

The updater (`webtyp/selfupdate`, a later plan) downloads both, verifies the signature with the public key compiled
into the app, and only then pulls `image@digest`. This plan adds that contract — the format, signing and verification —
to this repo. Nothing here downloads or pulls.

## Tools

```bash
go install webtyp.com/devflow/cmd/gotest@latest
go get webtyp.com/crypto@v0.0.30
```

Environment: `GOPRIVATE=webtyp.com/*,github.com/veltylabs/*`, `GOFLAGS=-mod=mod`, run `go mod tidy` after the `go get`.

## Ecosystem search

- Searched `manifest`, `sign`, `signature`, `digest`, `asym.Sign` over `webtyp/` and `veltylabs/`: nothing signs or
  verifies a release; `update.VerifyChecksum` (this repo) only detects corruption, not a forged release.
- `webtyp.com/crypto/asym` already signs and verifies (ECDSA P-256, SHA-256, works native and in WASM): **reuse** it.
  No new key algorithm is added.
- This repo owns "verify what an updater downloads" (`VerifyChecksum`, `Swap`, `Rollback`): **extend** it here, so the
  signer (`gorelease`) and the verifier (`selfupdate`) import one format and never re-implement it.

## Design gate

1. **Prior art.** [Sigstore cosign](https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md) signs an image
   by digest, never by tag, with a detached payload that must contain the digest. minisign/signify (unverified: no official page read in this session)
   (OpenBSD releases) sign a file's exact bytes and ship a detached signature next to it. [TUF](https://theupdateframework.github.io/specification/)
   signs metadata that names targets by hash and verifies it before downloading the target. All three: sign small
   metadata naming the artifact by hash, verify before fetching. This plan follows that, without cosign's transparency
   log or TUF's role hierarchy (one publisher, one private server).
2. **Novice names.** `update.SignManifest`, `update.VerifyManifest`, `update.Manifest{Version, Image, Digest}`,
   `Manifest.Reference()` (the `image@digest` string Docker pulls), `update.ManifestAsset`, `update.SignatureAsset`.
3. **Complexity ledger.** Concepts +1 (`Manifest`) · files the consumer touches +0 · call-site lines: sign 1, verify 1 ·
   ways to do the same thing +0 (`VerifyChecksum` stays for plain CLI binaries; manifests are for images).
4. **Where it belongs.** Here (see Ecosystem search). Key generation stays in `crypto/asym.GenerateKeyPair`.
5. **Deletes.** Nothing: new capability.

## APIs used

| Symbol | Exact signature | Tag | File |
|---|---|---|---|
| `asym.Sign` | `func Sign(message, privateKey []byte) (signature []byte, err error)` | `webtyp.com/crypto` v0.0.30 | `asym/asym.go` |
| `asym.Verify` | `func Verify(message, signature, publicKey []byte) (ok bool, err error)` — `err` only when the key cannot be parsed; a wrong signature is `ok == false, err == nil` | v0.0.30 | `asym/asym.go` |
| `asym.GenerateKeyPair` | `func GenerateKeyPair() (publicKey []byte, privateKey []byte, err error)` (tests only) | v0.0.30 | `asym/asym.go` |
| `parseSemver` (this repo, unexported) | `func parseSemver(v string) ([3]int, bool)` — trims a leading `v` and any `-pre`/`+build` suffix | — | `version.go` |

If a signature in the published tag differs from this table, stop and name the symbol in the PR; never adapt it by guessing.

## Stage 1 — `manifest.go` (new file, repo root, package `update`)

Write exactly this file:

```go
package update

import (
	"errors"
	"strings"

	"webtyp.com/crypto/asym"
)

// ManifestAsset is the name of the Release asset that holds the manifest text.
// Example: download(releaseURL + "/" + update.ManifestAsset)
const ManifestAsset = "manifest.txt"

// SignatureAsset is the name of the Release asset that holds the signature of
// ManifestAsset's exact bytes.
// Example: download(releaseURL + "/" + update.SignatureAsset)
const SignatureAsset = "manifest.sig"

// Errors returned by SignManifest and VerifyManifest; compare with err.Error().
const (
	ErrManifestVersion   = "manifest: version is not semver (vMAJOR.MINOR.PATCH)"
	ErrManifestImage     = "manifest: image is empty or carries a tag or digest"
	ErrManifestDigest    = "manifest: digest is not sha256:<64 lowercase hex>"
	ErrManifestFormat    = "manifest: malformed text"
	ErrManifestSignature = "manifest: signature does not match the public key"
)

const (
	manifestVersionKey = "version"
	manifestImageKey   = "image"
	manifestDigestKey  = "digest"
	manifestSeparator  = " "
	manifestLineEnd    = "\n"
	versionPrefix      = "v"
	digestPrefix       = "sha256:"
	digestHexLen       = 64
	digestHexChars     = "0123456789abcdef"
	imageDigestMark    = "@"
	imageTagMark       = ":"
	imagePathMark      = "/"
	imageForbidden     = "@ \t\n"
)

// Manifest names exactly one published version of an app's container image.
// Example: update.Manifest{Version: "v0.0.78", Image: "ghcr.io/acme/shop", Digest: "sha256:9f86d0…"}
type Manifest struct {
	Version string // semver tag, e.g. "v0.0.78"
	Image   string // repository without tag or digest, e.g. "ghcr.io/acme/shop"
	Digest  string // "sha256:" + 64 lowercase hex characters
}

// Reference is what Docker pulls: the image pinned to its digest.
// Example: m.Reference() == "ghcr.io/acme/shop@sha256:9f86d0…"
func (m Manifest) Reference() string {
	return m.Image + imageDigestMark + m.Digest
}

// SignManifest validates m and returns its canonical text and the signature of
// that text. Both are uploaded as Release assets (ManifestAsset, SignatureAsset).
// Example: text, sig, err := update.SignManifest(m, privateKey)
func SignManifest(m Manifest, privateKey []byte) (text, signature []byte, err error) {
	if err := m.validate(); err != nil {
		return nil, nil, err
	}
	text = m.encode()
	signature, err = asym.Sign(text, privateKey)
	if err != nil {
		return nil, nil, err
	}
	return text, signature, nil
}

// VerifyManifest checks signature over text with publicKey and only then parses
// text. A manifest is never read before its signature is verified.
// Example: m, err := update.VerifyManifest(text, sig, publicKey)
func VerifyManifest(text, signature, publicKey []byte) (Manifest, error) {
	ok, err := asym.Verify(text, signature, publicKey)
	if err != nil {
		return Manifest{}, err
	}
	if !ok {
		return Manifest{}, errors.New(ErrManifestSignature)
	}
	return parseManifest(text)
}

func (m Manifest) encode() []byte {
	return []byte(manifestVersionKey + manifestSeparator + m.Version + manifestLineEnd +
		manifestImageKey + manifestSeparator + m.Image + manifestLineEnd +
		manifestDigestKey + manifestSeparator + m.Digest + manifestLineEnd)
}

func (m Manifest) validate() error {
	if _, ok := parseSemver(m.Version); !ok || !strings.HasPrefix(m.Version, versionPrefix) {
		return errors.New(ErrManifestVersion)
	}
	if m.Image == "" || strings.ContainsAny(m.Image, imageForbidden) || strings.Contains(lastPathSegment(m.Image), imageTagMark) {
		return errors.New(ErrManifestImage)
	}
	if !validDigest(m.Digest) {
		return errors.New(ErrManifestDigest)
	}
	return nil
}

// lastPathSegment: a ":" after the last "/" is a tag ("shop:v1"); one before it is a registry port ("localhost:5000/shop").
func lastPathSegment(image string) string {
	if i := strings.LastIndex(image, imagePathMark); i >= 0 {
		return image[i+1:]
	}
	return image
}

func validDigest(d string) bool {
	hex, ok := strings.CutPrefix(d, digestPrefix)
	if !ok || len(hex) != digestHexLen {
		return false
	}
	for _, c := range hex {
		if !strings.ContainsRune(digestHexChars, c) {
			return false
		}
	}
	return true
}

// parseManifest accepts only the canonical text that encode produces.
func parseManifest(text []byte) (Manifest, error) {
	lines := strings.Split(strings.TrimSuffix(string(text), manifestLineEnd), manifestLineEnd)
	keys := [3]string{manifestVersionKey, manifestImageKey, manifestDigestKey}
	if len(lines) != len(keys) {
		return Manifest{}, errors.New(ErrManifestFormat)
	}
	var values [3]string
	for i, line := range lines {
		key, value, ok := strings.Cut(line, manifestSeparator)
		if !ok || key != keys[i] {
			return Manifest{}, errors.New(ErrManifestFormat)
		}
		values[i] = value
	}
	m := Manifest{Version: values[0], Image: values[1], Digest: values[2]}
	if err := m.validate(); err != nil {
		return Manifest{}, err
	}
	if string(m.encode()) != string(text) {
		return Manifest{}, errors.New(ErrManifestFormat)
	}
	return m, nil
}
```

Commit after this stage.

## Stage 2 — `tests/manifest_test.go` (new file, package `tests`)

Create `tests/` if missing. Imports: `testing`, `strings`, `webtyp.com/update`, `webtyp.com/crypto/asym`.
Use these fixtures (RFC-reserved and invented names only, never a real client):

```go
const (
	testImage  = "ghcr.io/acme/shop"
	testDigest = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
)
```

Each test: setup → call → expected.

| Test | Setup | Call | Expected |
|---|---|---|---|
| `TestManifest_RoundTrip` | `pub, priv := asym.GenerateKeyPair()`; `m := update.Manifest{"v0.0.78", testImage, testDigest}` | `text, sig, _ := update.SignManifest(m, priv)`; `got, err := update.VerifyManifest(text, sig, pub)` | `err == nil`, `got == m`, `string(text) == "version v0.0.78\nimage ghcr.io/acme/shop\ndigest " + testDigest + "\n"` |
| `TestManifest_Reference` | `m` as above | `m.Reference()` | `"ghcr.io/acme/shop@" + testDigest` |
| `TestManifest_TamperedText` | sign `m` | change the last hex character of the digest inside `text`, then `VerifyManifest` | `err.Error() == update.ErrManifestSignature` |
| `TestManifest_OtherKey` | sign with `priv`; second pair `pub2` | `VerifyManifest(text, sig, pub2)` | `update.ErrManifestSignature` |
| `TestManifest_NonCanonicalSigned` | `text := []byte("image " + testImage + "\nversion v0.0.78\ndigest " + testDigest + "\n")`; `sig, _ := asym.Sign(text, priv)` | `VerifyManifest(text, sig, pub)` | `update.ErrManifestFormat` |
| `TestManifest_ExtraLineSigned` | canonical text + `"note x\n"`, signed with `asym.Sign` | `VerifyManifest` | `update.ErrManifestFormat` |
| `TestManifest_Invalid` (table) | one `Manifest` per row, all other fields valid | `SignManifest(row, priv)` | error text per row, below |

`TestManifest_Invalid` rows (field changed → expected):

| Field | Value | Expected |
|---|---|---|
| Version | `"0.0.78"` | `ErrManifestVersion` |
| Version | `"v1.2"` | `ErrManifestVersion` |
| Image | `""` | `ErrManifestImage` |
| Image | `"ghcr.io/acme/shop:v1"` | `ErrManifestImage` |
| Image | `"ghcr.io/acme/shop@" + testDigest` | `ErrManifestImage` |
| Digest | `strings.ToUpper(testDigest)` | `ErrManifestDigest` |
| Digest | `"md5:" + testDigest[len("sha256:"):]` | `ErrManifestDigest` |
| Digest | `testDigest[:len(testDigest)-1]` | `ErrManifestDigest` |

And one valid row that must succeed: Image `"localhost:5000/acme/shop"` (a registry port is not a tag) → `err == nil`.

Commit after this stage.

## Stage 3 — docs

- `docs/API.md`: add one line each for `Manifest` (and its fields), `Manifest.Reference`, `SignManifest`, `VerifyManifest`,
  `ManifestAsset`, `SignatureAsset` and the five `ErrManifest*` constants, in the existing style.
- `README.md`: under "Features" add **Signed manifests (container images)**: one sentence on what it protects (a forged
  or moved release) and a 6-line example: the publisher calls `SignManifest`, uploads both assets; the updater calls
  `VerifyManifest` and pulls `m.Reference()`. Use `ghcr.io/acme/shop`.

Commit after this stage.

## Delivery check

1. `gotest` passes (it builds, vets and runs every test). A PR that does not compile, or whose tests could not run, is a failed delivery.
2. `grep -rn "SignManifest\|VerifyManifest" docs/API.md README.md` → both files mention both.
3. `git diff --stat main` lists only: `manifest.go`, `tests/manifest_test.go`, `docs/API.md`, `README.md`, `go.mod`, `go.sum`.

## Delivery rules

- Never pause to ask permission or report progress: when the delivery check passes, commit, push and open the PR. Stuck
  for 30 minutes: open the PR anyway, listing what fails.
- Commit after every stage. Never run `git reset`, `git restore`, `git checkout -- <file>` or `git stash` on your own work.
- Do not change `checksum.go`, `download.go`, `replace.go` or `version.go`.

## Stages

| # | Files | Result |
|---|---|---|
| 1 | `manifest.go` | Format, signing and verification |
| 2 | `tests/manifest_test.go` | Round trip, tampering, wrong key, non-canonical text, invalid fields |
| 3 | `docs/API.md`, `README.md` | Documented API |
