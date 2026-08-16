package persistence

import (
	"context"
	"errors"
	"time"
)

var ErrUnsupported = errors.New("persistence scanning requires Linux")

type Level string

const (
	LevelInfo    Level = "info"
	LevelReview  Level = "review"
	LevelWarning Level = "warning"
)

type Provenance string

const (
	ProvenancePackageMatch    Provenance = "package-match"
	ProvenancePackageModified Provenance = "package-modified"
	ProvenancePackageOwned    Provenance = "package-owned"
	ProvenanceLocal           Provenance = "local"
	ProvenanceGenerated       Provenance = "generated"
	ProvenanceUnverified      Provenance = "unverified"
)

type Finding struct {
	ID              string         `json:"id"`
	Level           Level          `json:"level"`
	Mechanism       string         `json:"mechanism"`
	Name            string         `json:"name"`
	Path            string         `json:"path"`
	User            string         `json:"user,omitempty"`
	Command         string         `json:"command,omitempty"`
	Schedule        string         `json:"schedule,omitempty"`
	Source          string         `json:"source"`
	Scope           string         `json:"scope,omitempty"`
	Unit            string         `json:"unit,omitempty"`
	Role            string         `json:"role,omitempty"`
	Enablement      string         `json:"enablement,omitempty"`
	ResolvedPath    string         `json:"resolved_path,omitempty"`
	RelatedPaths    []string       `json:"related_paths,omitempty"`
	Provenance      Provenance     `json:"provenance"`
	Package         string         `json:"package,omitempty"`
	PackageManager  string         `json:"package_manager,omitempty"`
	Integrity       string         `json:"integrity,omitempty"`
	ReferencedFiles []FileEvidence `json:"referenced_files,omitempty"`
	Reason          string         `json:"reason"`
	Recommendation  string         `json:"recommendation"`
}

type FileEvidence struct {
	Path           string     `json:"path"`
	Provenance     Provenance `json:"provenance"`
	Package        string     `json:"package,omitempty"`
	PackageManager string     `json:"package_manager,omitempty"`
	Integrity      string     `json:"integrity,omitempty"`
}

type Result struct {
	ScannedAt      time.Time `json:"scanned_at"`
	Findings       []Finding `json:"findings"`
	Warnings       []string  `json:"warnings,omitempty"`
	PackageManager string    `json:"package_manager,omitempty"`
}

type Scanner interface {
	Scan(context.Context) (Result, error)
}
