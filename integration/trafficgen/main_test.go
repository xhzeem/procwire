package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xhzeem/procwire/integration/fixture"
)

func TestInstallPersistenceFixturesUsesManifestDrivenNames(t *testing.T) {
	root := t.TempDir()
	modified := "/lib/systemd/system/package.timer"
	modifiedPath := rootedPath(root, modified)
	if err := os.MkdirAll(filepath.Dir(modifiedPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modifiedPath, []byte("[Timer]\nOnBootSec=1m\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := fixture.Manifest{}
	if err := installPersistenceFixtures(options{
		fixtureRoot:         root,
		modifiedPackageFile: modified,
	}, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.ServiceUnits) != 2 || len(manifest.TimerUnits) != 2 || len(manifest.CronPaths) != 2 {
		t.Fatalf("fixture manifest = %#v", manifest)
	}
	for _, unit := range append(append([]string{}, manifest.ServiceUnits...), manifest.TimerUnits...) {
		if _, err := os.Stat(rootedPath(root, "/etc/systemd/system/"+unit)); err != nil {
			t.Fatalf("fixture unit %s: %v", unit, err)
		}
	}
	for _, path := range manifest.CronPaths {
		if _, err := os.Stat(rootedPath(root, path)); err != nil {
			t.Fatalf("cron fixture %s: %v", path, err)
		}
	}
	if manifest.ModifiedPackageFile != modified {
		t.Fatalf("modified package file = %q", manifest.ModifiedPackageFile)
	}
}

func TestRootedPathCannotEscapeFixtureRoot(t *testing.T) {
	root := t.TempDir()
	got := rootedPath(root, "../../outside")
	want := filepath.Join(root, "outside")
	if got != want {
		t.Fatalf("rooted path = %q, want %q", got, want)
	}
}

func TestCanonicalFixturePathIsRelativeToFixtureRoot(t *testing.T) {
	root := t.TempDir()
	target := rootedPath(root, "/usr/lib/systemd/system/example.timer")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := canonicalFixturePath(root, target, "/fallback"); got != "/usr/lib/systemd/system/example.timer" {
		t.Fatalf("canonical fixture path = %q", got)
	}
}
