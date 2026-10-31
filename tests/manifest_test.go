package tests

import (
	"strings"
	"testing"

	"webtyp.com/crypto/asym"
	"webtyp.com/update"
)

const (
	testImage   = "ghcr.io/acme/shop"
	testDigest  = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	testCompose = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
)

func TestManifest_RoundTrip(t *testing.T) {
	pub, priv, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	m := update.Manifest{Version: "v0.0.78", Image: testImage, Digest: testDigest, ComposeDigest: testCompose}
	text, sig, err := update.SignManifest(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := update.VerifyManifest(text, sig, pub)
	if err != nil {
		t.Fatal(err)
	}
	if got != m {
		t.Fatalf("got %v, want %v", got, m)
	}
	wantText := "version v0.0.78\nimage ghcr.io/acme/shop\ndigest " + testDigest + "\ncompose " + testCompose + "\n"
	if string(text) != wantText {
		t.Fatalf("got text %q, want %q", text, wantText)
	}
}

func TestManifest_Reference(t *testing.T) {
	m := update.Manifest{Version: "v0.0.78", Image: testImage, Digest: testDigest, ComposeDigest: testCompose}
	got := m.Reference()
	want := "ghcr.io/acme/shop@" + testDigest
	if got != want {
		t.Fatalf("got reference %q, want %q", got, want)
	}
}

func TestManifest_TamperedText(t *testing.T) {
	pub, priv, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	m := update.Manifest{Version: "v0.0.78", Image: testImage, Digest: testDigest, ComposeDigest: testCompose}
	text, sig, err := update.SignManifest(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	// change the last hex character
	text[len(text)-2] = '9' // Before '\n'
	_, err = update.VerifyManifest(text, sig, pub)
	if err == nil || err.Error() != update.ErrManifestSignature {
		t.Fatalf("got err %v, want %s", err, update.ErrManifestSignature)
	}
}

func TestManifest_OtherKey(t *testing.T) {
	_, priv, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	m := update.Manifest{Version: "v0.0.78", Image: testImage, Digest: testDigest, ComposeDigest: testCompose}
	text, sig, err := update.SignManifest(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	_, err = update.VerifyManifest(text, sig, pub2)
	if err == nil || err.Error() != update.ErrManifestSignature {
		t.Fatalf("got err %v, want %s", err, update.ErrManifestSignature)
	}
}

func TestManifest_NonCanonicalSigned(t *testing.T) {
	pub, priv, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	text := []byte("image " + testImage + "\nversion v0.0.78\ndigest " + testDigest + "\ncompose " + testCompose + "\n")
	sig, err := asym.Sign(text, priv)
	if err != nil {
		t.Fatal(err)
	}
	_, err = update.VerifyManifest(text, sig, pub)
	if err == nil || err.Error() != update.ErrManifestFormat {
		t.Fatalf("got err %v, want %s", err, update.ErrManifestFormat)
	}
}

func TestManifest_ExtraLineSigned(t *testing.T) {
	pub, priv, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	m := update.Manifest{Version: "v0.0.78", Image: testImage, Digest: testDigest, ComposeDigest: testCompose}
	// SignManifest doesn't expose encode(), we just want canonical + extra
	// However, we can construct the canonical string manually or get it by SignManifest
	text, _, err := update.SignManifest(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	text = append(text, []byte("note x\n")...)
	sig, err := asym.Sign(text, priv)
	if err != nil {
		t.Fatal(err)
	}
	_, err = update.VerifyManifest(text, sig, pub)
	if err == nil || err.Error() != update.ErrManifestFormat {
		t.Fatalf("got err %v, want %s", err, update.ErrManifestFormat)
	}
}

func TestManifest_Invalid(t *testing.T) {
	_, priv, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		m    update.Manifest
		want string
	}{
		{update.Manifest{Version: "0.0.78", Image: testImage, Digest: testDigest, ComposeDigest: testCompose}, update.ErrManifestVersion},
		{update.Manifest{Version: "v1.2", Image: testImage, Digest: testDigest, ComposeDigest: testCompose}, update.ErrManifestVersion},
		{update.Manifest{Version: "v0.0.78", Image: "", Digest: testDigest, ComposeDigest: testCompose}, update.ErrManifestImage},
		{update.Manifest{Version: "v0.0.78", Image: "ghcr.io/acme/shop:v1", Digest: testDigest, ComposeDigest: testCompose}, update.ErrManifestImage},
		{update.Manifest{Version: "v0.0.78", Image: "ghcr.io/acme/shop@" + testDigest, Digest: testDigest, ComposeDigest: testCompose}, update.ErrManifestImage},
		{update.Manifest{Version: "v0.0.78", Image: testImage, Digest: strings.ToUpper(testDigest), ComposeDigest: testCompose}, update.ErrManifestDigest},
		{update.Manifest{Version: "v0.0.78", Image: testImage, Digest: "md5:" + testDigest[len("sha256:"):], ComposeDigest: testCompose}, update.ErrManifestDigest},
		{update.Manifest{Version: "v0.0.78", Image: testImage, Digest: testDigest[:len(testDigest)-1], ComposeDigest: testCompose}, update.ErrManifestDigest},
		{update.Manifest{Version: "v0.0.78", Image: testImage, Digest: testDigest, ComposeDigest: ""}, update.ErrManifestCompose},
		{update.Manifest{Version: "v0.0.78", Image: testImage, Digest: testDigest, ComposeDigest: "md5:" + testCompose[len("sha256:"):]}, update.ErrManifestCompose},
	}

	for _, tt := range tests {
		_, _, err := update.SignManifest(tt.m, priv)
		if err == nil || err.Error() != tt.want {
			t.Errorf("SignManifest(%v) err = %v, want %s", tt.m, err, tt.want)
		}
	}

	// And one valid row that must succeed
	validM := update.Manifest{Version: "v0.0.78", Image: "localhost:5000/acme/shop", Digest: testDigest, ComposeDigest: testCompose}
	_, _, err = update.SignManifest(validM, priv)
	if err != nil {
		t.Errorf("SignManifest(%v) err = %v, want nil", validM, err)
	}
}

func TestDigest(t *testing.T) {
	got := update.Digest([]byte("abc"))
	if got != testCompose {
		t.Errorf("got %q, want %q", got, testCompose)
	}
}

func TestCheckCompose(t *testing.T) {
	m := update.Manifest{ComposeDigest: testCompose}
	if err := m.CheckCompose([]byte("abc")); err != nil {
		t.Errorf("CheckCompose(abc) err = %v, want nil", err)
	}
	if err := m.CheckCompose([]byte("abd")); err == nil || err.Error() != update.ErrComposeMismatch {
		t.Errorf("CheckCompose(abd) err = %v, want %s", err, update.ErrComposeMismatch)
	}
}
