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
