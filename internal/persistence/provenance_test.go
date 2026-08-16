package persistence

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDPKGVerifierDetectsMatchAndModification(t *testing.T) {
	root := t.TempDir()
	infoDir := filepath.Join(root, "var/lib/dpkg/info")
	unitDir := filepath.Join(root, "usr/lib/systemd/system")
	if err := os.MkdirAll(infoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := []byte("[Service]\nExecStart=/usr/bin/example\n")
	unitPath := filepath.Join(unitDir, "example.service")
	if err := os.WriteFile(unitPath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := md5.Sum(content)
	if err := os.WriteFile(filepath.Join(infoDir, "example.list"), []byte("/usr/lib/systemd/system/example.service\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf("%x  usr/lib/systemd/system/example.service\n", sum)
	if err := os.WriteFile(filepath.Join(infoDir, "example.md5sums"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	statusPath := filepath.Join(root, "var/lib/dpkg/status")
	if err := os.WriteFile(statusPath, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	verifier, err := loadDPKGVerifier(root)
	if err != nil {
		t.Fatalf("load verifier: %v", err)
	}
	verified := verifier.Verify("/usr/lib/systemd/system/example.service")
	if verified.provenance != ProvenancePackageMatch || verified.packageName != "example" {
		t.Fatalf("verification = %#v", verified)
	}

	if err := os.WriteFile(unitPath, append(content, []byte("# changed\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	modified := verifier.Verify("/usr/lib/systemd/system/example.service")
	if modified.provenance != ProvenancePackageModified {
		t.Fatalf("modified verification = %#v", modified)
	}

	local := verifier.Verify("/etc/systemd/system/lookalike.service")
	if local.provenance != ProvenanceLocal {
		t.Fatalf("unowned verification = %#v", local)
	}
}

func TestManifestVerifierHandlesUsrMergeAlias(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "usr/lib/systemd/system/alias.service")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/lib", filepath.Join(root, "lib")); err != nil {
		t.Fatal(err)
	}
	content := []byte("unit")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := md5.Sum(content)
	verifier := &manifestVerifier{
		name: "test",
		root: root,
		records: map[string]packageRecord{
			"/lib/systemd/system/alias.service": {packageName: "alias", algorithm: "md5", digest: sum[:]},
		},
	}
	result := verifier.Verify("/usr/lib/systemd/system/alias.service")
	if result.provenance != ProvenancePackageMatch {
		t.Fatalf("alias verification = %#v", result)
	}
}

func TestAPKQ1SHA256_160Digest(t *testing.T) {
	content := []byte("apk file content")
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	digest, err := digestFile(path, "sha256-160")
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != 20 {
		t.Fatalf("digest length = %d, want 20", len(digest))
	}
	encoded := "Q1" + base64.StdEncoding.EncodeToString(digest)
	decoded, algorithm := decodeAPKDigest(encoded, true)
	if algorithm != "sha256-160" || !bytes.Equal(decoded, digest) {
		t.Fatalf("decoded %q digest = %x", algorithm, decoded)
	}
}

func TestIncompleteManifestDoesNotClaimPathIsLocal(t *testing.T) {
	verifier := &manifestVerifier{name: "test", incomplete: true, records: map[string]packageRecord{}}
	result := verifier.Verify("/etc/systemd/system/unknown.service")
	if result.provenance != ProvenanceUnverified {
		t.Fatalf("incomplete verification = %#v", result)
	}
}

func TestManifestAliasRequiresUsrMerge(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr/lib/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "lib/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}
	verifier := &manifestVerifier{
		name: "test",
		root: root,
		records: map[string]packageRecord{
			"/lib/systemd/system/example.service": {packageName: "example"},
		},
	}
	result := verifier.Verify("/usr/lib/systemd/system/example.service")
	if result.provenance != ProvenanceLocal {
		t.Fatalf("split /usr verification = %#v", result)
	}
}
