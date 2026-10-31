---
PLAN: "feat!: the signed manifest also carries the compose.yaml digest"
EXECUTOR: jules
REVIEWER: none
STATUS: running
SESSION: 4564400357546458216
---

> Read AGENTS.md at the repo root before any change.
> **Finish by yourself:** when the delivery check passes, commit, push and open the pull request. Never ask whether to
> proceed or finalize — nobody answers, and a session that waits ends without your work.

# Compose digest in the manifest

## Context

A self-hosted app's Release carries the image reference, a `manifest.txt` signed by the publisher, and the
`compose.yaml` the server runs. Today the signature covers only the image digest: a `compose.yaml` altered in the
Release (for example one that mounts the host's root into a container) would be installed without notice. This plan
adds the compose file's digest to the manifest, so the same signature protects both. Nothing in production reads
manifests yet; the canonical text changes from three lines to four.

## Tools

```bash
go install webtyp.com/devflow/cmd/gotest@latest
```

## Stage 1 — tests first (`tests/manifest_test.go`)

- Every `update.Manifest{…}` in the file gains `ComposeDigest: testCompose` where
  `const testCompose = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"` (the SHA-256 of `abc`).
- `TestManifest_RoundTrip`: the expected text becomes
  `"version v0.0.78\nimage ghcr.io/acme/shop\ndigest " + testDigest + "\ncompose " + testCompose + "\n"`.
- `TestManifest_Invalid`: add rows `ComposeDigest: ""` → `update.ErrManifestCompose`; `ComposeDigest: "md5:x"` → `ErrManifestCompose`.
- `TestManifest_NonCanonicalSigned` and `TestManifest_ExtraLineSigned`: build their texts with the four lines (keep what
  each one tests: wrong order / one extra line).
- New `TestDigest`: `update.Digest([]byte("abc")) == testCompose`.
- New `TestCheckCompose`: `m.CheckCompose([]byte("abc")) == nil`; `m.CheckCompose([]byte("abd"))` → error text
  `update.ErrComposeMismatch`.

Commit (red).

## Stage 2 — `manifest.go`

- `Manifest` gains `ComposeDigest string // "sha256:" + hex of compose.yaml, see Digest`.
- Constants: `ComposeAsset = "compose.yaml"` (with a comment like `ManifestAsset`'s);
  `ErrManifestCompose = "manifest: compose digest is not sha256:<64 lowercase hex>"`;
  `ErrComposeMismatch = "manifest: compose.yaml does not match the signed digest"`; private `manifestComposeKey = "compose"`.
- `encode` appends `manifestComposeKey + manifestSeparator + m.ComposeDigest + manifestLineEnd`.
- `validate` ends with `if !validDigest(m.ComposeDigest) { return errors.New(ErrManifestCompose) }`.
- `parseManifest`: `keys` and `values` become `[4]string` with `manifestComposeKey` last, and the manifest is built with
  `ComposeDigest: values[3]`.
- Add:

```go
// Digest is the content address the manifest uses: "sha256:" + lowercase hex.
// Example: m.ComposeDigest = update.Digest(composeYAML)
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return digestPrefix + hex.EncodeToString(sum[:])
}

// CheckCompose reports whether data is the compose file this manifest signed.
// Example: if err := m.CheckCompose(composeYAML); err != nil { refuse }
func (m Manifest) CheckCompose(data []byte) error {
	if Digest(data) != m.ComposeDigest {
		return errors.New(ErrComposeMismatch)
	}
	return nil
}
```

(imports `crypto/sha256`, `encoding/hex`.) Run `gotest`: green. Commit.

## Stage 3 — docs

`docs/API.md`: add `ComposeDigest`, `ComposeAsset`, `Digest`, `CheckCompose`, `ErrManifestCompose`, `ErrComposeMismatch`.
`README.md` «Signed manifests»: the manifest names the image **and** the compose file; the updater calls
`CheckCompose` before using the downloaded `compose.yaml`. Commit.

## Delivery check

1. `gotest` passes. A PR that does not compile, or whose tests could not run, is a failed delivery.
2. `git diff --stat main` lists only `manifest.go`, `tests/manifest_test.go`, `docs/API.md`, `README.md`.

## Delivery rules

- Commit after every stage. Never run `git reset`, `git restore`, `git checkout -- <file>` or `git stash` on your own work.
- Stuck for 30 minutes: open the PR anyway, listing what fails.

## Stages

| # | Files | Result |
|---|---|---|
| 1 | `tests/manifest_test.go` | Four-line manifest, compose digest checks; red |
| 2 | `manifest.go` | `ComposeDigest`, `Digest`, `CheckCompose`; green |
| 3 | `docs/API.md`, `README.md` | Documented |
