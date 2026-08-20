package persistence

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/md5"  // Package manifests from dpkg and pacman may use MD5.
	"crypto/sha1" // APK v2 Q1 checksums use SHA-1.
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type verification struct {
	provenance  Provenance
	manager     string
	packageName string
	detail      string
}

type packageRecord struct {
	packageName string
	algorithm   string
	digest      []byte
}

type packageVerifier interface {
	Name() string
	Verify(string) verification
}

// FileVerifier exposes package-manifest checks to other host inventory
// collectors without exposing the package database implementation.
type FileVerifier interface {
	Name() string
	Verify(string) FileEvidence
	VerifyContent(string, io.Reader) FileEvidence
}

type exportedFileVerifier struct {
	inner packageVerifier
}

type manifestVerifier struct {
	name       string
	root       string
	records    map[string]packageRecord
	incomplete bool
	warnings   []string
}

type unknownVerifier struct {
	detail string
}

func (v unknownVerifier) Name() string { return "unsupported" }

func (v unknownVerifier) Verify(string) verification {
	return verification{
		provenance: ProvenanceUnverified,
		manager:    v.Name(),
		detail:     v.detail,
	}
}

func newNativePackageVerifier(root string) (packageVerifier, []string) {
	loaders := []struct {
		marker string
		load   func(string) (*manifestVerifier, error)
	}{
		{marker: "/var/lib/dpkg/info", load: loadDPKGVerifier},
		{marker: "/var/lib/pacman/local", load: loadPacmanVerifier},
		{marker: "/lib/apk/db/installed", load: loadAPKVerifier},
	}
	for _, loader := range loaders {
		if _, err := os.Stat(rooted(root, loader.marker)); err != nil {
			continue
		}
		verifier, err := loader.load(root)
		if err != nil {
			return unknownVerifier{detail: "package database was detected but could not be parsed"}, []string{err.Error()}
		}
		return verifier, verifier.warnings
	}
	return unknownVerifier{detail: "no supported native package manifest was found"}, nil
}

// NewFileVerifier loads the native package manifest rooted at root. VerifyContent
// compares an already-open live file, such as /proc/PID/exe, with that manifest.
func NewFileVerifier(root string) (FileVerifier, []string) {
	verifier, warnings := newNativePackageVerifier(root)
	return exportedFileVerifier{inner: verifier}, warnings
}

func (v exportedFileVerifier) Name() string { return v.inner.Name() }

func (v exportedFileVerifier) Verify(path string) FileEvidence {
	return fileEvidence(path, v.inner.Verify(path))
}

func (v exportedFileVerifier) VerifyContent(path string, content io.Reader) FileEvidence {
	if verifier, ok := v.inner.(interface {
		VerifyContent(string, io.Reader) verification
	}); ok {
		return fileEvidence(path, verifier.VerifyContent(path, content))
	}
	return fileEvidence(path, v.inner.Verify(path))
}

func fileEvidence(path string, verified verification) FileEvidence {
	return FileEvidence{
		Path:           path,
		Provenance:     verified.provenance,
		Package:        verified.packageName,
		PackageManager: verified.manager,
		Integrity:      verified.detail,
	}
}

func (v *manifestVerifier) Name() string { return v.name }

func (v *manifestVerifier) Verify(path string) verification {
	path, record, result, found := v.lookup(path)
	if !found {
		return result
	}
	if record.algorithm == "" || len(record.digest) == 0 {
		return result
	}
	actualPath := rooted(v.root, path)
	info, err := os.Lstat(actualPath)
	if err != nil {
		result.provenance = ProvenancePackageModified
		result.detail = "package-owned path is missing or unreadable: " + err.Error()
		return result
	}
	if !info.Mode().IsRegular() {
		return result
	}
	digest, err := digestFile(actualPath, record.algorithm)
	if err != nil {
		result.provenance = ProvenanceUnverified
		result.detail = "could not hash package-owned path: " + err.Error()
		return result
	}
	if !bytes.Equal(digest, record.digest) {
		result.provenance = ProvenancePackageModified
		result.detail = fmt.Sprintf("file digest does not match the local %s package manifest", v.name)
		return result
	}
	result.provenance = ProvenancePackageMatch
	result.detail = fmt.Sprintf("%s digest matches the local %s package manifest", strings.ToUpper(record.algorithm), v.name)
	return result
}

func (v *manifestVerifier) VerifyContent(path string, content io.Reader) verification {
	_, record, result, found := v.lookup(path)
	if !found || record.algorithm == "" || len(record.digest) == 0 {
		return result
	}
	digest, err := digestReader(content, record.algorithm)
	if err != nil {
		result.provenance = ProvenanceUnverified
		result.detail = "could not hash live package-owned content: " + err.Error()
		return result
	}
	if !bytes.Equal(digest, record.digest) {
		result.provenance = ProvenancePackageModified
		result.detail = fmt.Sprintf("live file digest does not match the local %s package manifest", v.name)
		return result
	}
	result.provenance = ProvenancePackageMatch
	result.detail = fmt.Sprintf("live %s digest matches the local %s package manifest", strings.ToUpper(record.algorithm), v.name)
	return result
}

func (v *manifestVerifier) lookup(path string) (string, packageRecord, verification, bool) {
	path = normalizeManifestPath(path)
	record, found := v.records[path]
	if !found {
		for _, alias := range manifestAliases(v.root, path) {
			if record, found = v.records[alias]; found {
				break
			}
		}
	}
	if !found {
		if v.incomplete {
			return path, packageRecord{}, verification{
				provenance: ProvenanceUnverified,
				manager:    v.name,
				detail:     "package metadata was only partially readable, so path ownership cannot be established",
			}, false
		}
		return path, packageRecord{}, verification{
			provenance: ProvenanceLocal,
			manager:    v.name,
			detail:     "path is not owned by any entry in the local package manifest",
		}, false
	}
	return path, record, verification{
		provenance:  ProvenancePackageOwned,
		manager:     v.name,
		packageName: record.packageName,
		detail:      "path is owned by an installed package, but no file digest is available",
	}, true
}

func loadDPKGVerifier(root string) (*manifestVerifier, error) {
	verifier := &manifestVerifier{name: "dpkg", root: root, records: make(map[string]packageRecord)}
	infoDir := rooted(root, "/var/lib/dpkg/info")
	entries, err := os.ReadDir(infoDir)
	if err != nil {
		return nil, fmt.Errorf("read dpkg metadata: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".list") {
			continue
		}
		packageName := strings.TrimSuffix(entry.Name(), ".list")
		data, err := os.ReadFile(filepath.Join(infoDir, entry.Name()))
		if err != nil {
			verifier.warn("cannot read dpkg ownership list %s: %v", entry.Name(), err)
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			path := normalizeManifestPath(strings.TrimSpace(line))
			if path != "/" {
				verifier.add(path, packageRecord{packageName: packageName})
			}
		}
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md5sums") {
			continue
		}
		packageName := strings.TrimSuffix(entry.Name(), ".md5sums")
		data, err := os.ReadFile(filepath.Join(infoDir, entry.Name()))
		if err != nil {
			verifier.warn("cannot read dpkg digest list %s: %v", entry.Name(), err)
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if len(line) < 34 {
				continue
			}
			digest, err := hex.DecodeString(line[:32])
			if err != nil {
				verifier.warn("invalid digest in dpkg metadata %s", entry.Name())
				continue
			}
			path := normalizeManifestPath(strings.TrimSpace(line[32:]))
			verifier.add(path, packageRecord{packageName: packageName, algorithm: "md5", digest: digest})
		}
	}
	if err := verifier.loadDPKGConffiles(rooted(root, "/var/lib/dpkg/status")); err != nil {
		verifier.warn("cannot read dpkg conffile metadata: %v", err)
	}
	return verifier, nil
}

func (v *manifestVerifier) loadDPKGConffiles(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, paragraph := range strings.Split(string(data), "\n\n") {
		packageName := ""
		installed := false
		inConffiles := false
		for _, line := range strings.Split(paragraph, "\n") {
			switch {
			case strings.HasPrefix(line, "Package:"):
				packageName = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
			case strings.HasPrefix(line, "Status:"):
				installed = strings.Contains(line, "install ok installed")
			case line == "Conffiles:":
				inConffiles = true
			case inConffiles && strings.HasPrefix(line, " "):
				fields := strings.Fields(line)
				if len(fields) < 2 || !installed || packageName == "" {
					continue
				}
				digest, err := hex.DecodeString(fields[1])
				if err == nil {
					v.add(normalizeManifestPath(fields[0]), packageRecord{packageName: packageName, algorithm: "md5", digest: digest})
				}
			case len(line) > 0 && line[0] != ' ':
				inConffiles = false
			}
		}
	}
	return nil
}

func loadPacmanVerifier(root string) (*manifestVerifier, error) {
	verifier := &manifestVerifier{name: "pacman", root: root, records: make(map[string]packageRecord)}
	database := rooted(root, "/var/lib/pacman/local")
	packages, err := os.ReadDir(database)
	if err != nil {
		return nil, fmt.Errorf("read pacman metadata: %w", err)
	}
	for _, packageDir := range packages {
		if !packageDir.IsDir() {
			continue
		}
		directory := filepath.Join(database, packageDir.Name())
		packageName := pacmanPackageName(filepath.Join(directory, "desc"), packageDir.Name())
		data, err := os.ReadFile(filepath.Join(directory, "files"))
		if err == nil {
			section := ""
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "%") && strings.HasSuffix(line, "%") {
					section = line
					continue
				}
				if line == "" {
					continue
				}
				switch section {
				case "%FILES%":
					if !strings.HasSuffix(line, "/") {
						verifier.add(normalizeManifestPath(line), packageRecord{packageName: packageName})
					}
				case "%BACKUP%":
					fields := strings.Split(line, "\t")
					if len(fields) == 2 {
						digest, algorithm := decodeHexDigest(fields[1])
						verifier.add(normalizeManifestPath(fields[0]), packageRecord{packageName: packageName, algorithm: algorithm, digest: digest})
					}
				}
			}
		} else {
			verifier.warn("cannot read pacman file list for %s: %v", packageName, err)
		}
		if err := loadPacmanMtree(verifier, filepath.Join(directory, "mtree"), packageName); err != nil && !os.IsNotExist(err) {
			verifier.warn("cannot read pacman mtree for %s: %v", packageName, err)
		}
	}
	return verifier, nil
}

func pacmanPackageName(path, fallback string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return fallback
	}
	lines := strings.Split(string(data), "\n")
	for index, line := range lines {
		if line == "%NAME%" && index+1 < len(lines) {
			return lines[index+1]
		}
	}
	return fallback
}

func loadPacmanMtree(verifier *manifestVerifier, path, packageName string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer reader.Close()
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "/set") || strings.HasPrefix(line, "/unset") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "./") {
			continue
		}
		path := normalizeManifestPath(decodeMtreePath(strings.TrimPrefix(fields[0], "./")))
		record := packageRecord{packageName: packageName}
		for _, field := range fields[1:] {
			key, value, found := strings.Cut(field, "=")
			if !found {
				continue
			}
			if key == "sha256digest" {
				record.digest, _ = hex.DecodeString(value)
				record.algorithm = "sha256"
				break
			}
			if key == "md5digest" && record.algorithm == "" {
				record.digest, _ = hex.DecodeString(value)
				record.algorithm = "md5"
			}
		}
		verifier.add(path, record)
	}
	return scanner.Err()
}

func decodeMtreePath(value string) string {
	replacer := strings.NewReplacer("\\040", " ", "\\011", "\t", "\\134", "\\")
	return replacer.Replace(value)
}

func loadAPKVerifier(root string) (*manifestVerifier, error) {
	verifier := &manifestVerifier{name: "apk", root: root, records: make(map[string]packageRecord)}
	file, err := os.Open(rooted(root, "/lib/apk/db/installed"))
	if err != nil {
		return nil, fmt.Errorf("read apk metadata: %w", err)
	}
	defer file.Close()
	packageName := ""
	directory := ""
	lastPath := ""
	sha256_160 := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch key {
		case "P":
			packageName = value
		case "F":
			directory = value
		case "R":
			lastPath = normalizeManifestPath(filepath.Join(directory, value))
			sha256_160 = false
			verifier.add(lastPath, packageRecord{packageName: packageName})
		case "f":
			sha256_160 = strings.Contains(value, "S")
		case "Z":
			if lastPath == "" {
				continue
			}
			digest, algorithm := decodeAPKDigest(value, sha256_160)
			if len(digest) > 0 {
				verifier.add(lastPath, packageRecord{packageName: packageName, algorithm: algorithm, digest: digest})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan apk metadata: %w", err)
	}
	return verifier, nil
}

func decodeAPKDigest(value string, sha256_160 bool) ([]byte, string) {
	if len(value) < 3 || value[0] != 'Q' {
		return nil, ""
	}
	algorithm := ""
	switch value[1] {
	case '1':
		if sha256_160 {
			algorithm = "sha256-160"
		} else {
			algorithm = "sha1"
		}
	case '2':
		algorithm = "sha256"
	default:
		return nil, ""
	}
	digest, err := base64.StdEncoding.DecodeString(value[2:])
	if err != nil {
		return nil, ""
	}
	return digest, algorithm
}

func (v *manifestVerifier) add(path string, record packageRecord) {
	path = normalizeManifestPath(path)
	if path == "/" || path == "." {
		return
	}
	current, exists := v.records[path]
	if !exists || (current.algorithm == "" && record.algorithm != "") {
		v.records[path] = record
	}
}

func (v *manifestVerifier) warn(format string, values ...any) {
	v.incomplete = true
	v.warnings = append(v.warnings, fmt.Sprintf(format, values...))
}

func digestFile(path, algorithm string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return digestReader(file, algorithm)
}

func digestReader(reader io.Reader, algorithm string) ([]byte, error) {
	var digest hash.Hash
	switch algorithm {
	case "md5":
		digest = md5.New()
	case "sha1":
		digest = sha1.New()
	case "sha256", "sha256-160":
		digest = sha256.New()
	default:
		return nil, fmt.Errorf("unsupported digest algorithm %q", algorithm)
	}
	if _, err := io.Copy(digest, reader); err != nil {
		return nil, err
	}
	result := digest.Sum(nil)
	if algorithm == "sha256-160" {
		result = result[:sha1.Size]
	}
	return result, nil
}

func decodeHexDigest(value string) ([]byte, string) {
	digest, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, ""
	}
	switch len(digest) {
	case md5.Size:
		return digest, "md5"
	case sha1.Size:
		return digest, "sha1"
	case sha256.Size:
		return digest, "sha256"
	default:
		return nil, ""
	}
}

func normalizeManifestPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !filepath.IsAbs(path) {
		path = "/" + path
	}
	return filepath.Clean(path)
}

func rooted(root, path string) string {
	if root == "" || root == "/" {
		return path
	}
	return filepath.Join(root, strings.TrimPrefix(path, "/"))
}

func manifestAliases(root, path string) []string {
	pairs := [][2]string{
		{"/usr/lib/", "/lib/"},
		{"/usr/lib64/", "/lib64/"},
		{"/usr/bin/", "/bin/"},
		{"/usr/sbin/", "/sbin/"},
	}
	aliases := make([]string, 0, 1)
	for _, pair := range pairs {
		leftDirectory := strings.TrimSuffix(pair[0], "/")
		rightDirectory := strings.TrimSuffix(pair[1], "/")
		if !sameDirectory(rooted(root, leftDirectory), rooted(root, rightDirectory)) {
			continue
		}
		switch {
		case strings.HasPrefix(path, pair[0]):
			aliases = append(aliases, pair[1]+strings.TrimPrefix(path, pair[0]))
		case strings.HasPrefix(path, pair[1]):
			aliases = append(aliases, pair[0]+strings.TrimPrefix(path, pair[1]))
		}
	}
	return aliases
}

func sameDirectory(left, right string) bool {
	leftInfo, err := os.Stat(left)
	if err != nil {
		return false
	}
	rightInfo, err := os.Stat(right)
	if err != nil {
		return false
	}
	return os.SameFile(leftInfo, rightInfo)
}
