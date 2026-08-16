//go:build linux

package persistence

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type linuxScanner struct {
	home        string
	currentUser string
	verifier    packageVerifier
}

type systemdRoot struct {
	path      string
	source    string
	scope     string
	user      string
	reason    string
	generated bool
}

func NewScanner() Scanner {
	home, _ := os.UserHomeDir()
	currentUser := "current user"
	if account, err := user.Current(); err == nil && account.Username != "" {
		currentUser = account.Username
	}
	return &linuxScanner{home: home, currentUser: currentUser}
}

func (s *linuxScanner) Scan(ctx context.Context) (Result, error) {
	result := Result{ScannedAt: time.Now()}
	verifier, warnings := newNativePackageVerifier("/")
	s.verifier = verifier
	result.PackageManager = verifier.Name()
	result.Warnings = append(result.Warnings, warnings...)
	s.scanSystemd(ctx, &result)
	if err := ctx.Err(); err != nil {
		return result, err
	}
	s.scanCron(ctx, &result)
	sort.Slice(result.Findings, func(i, j int) bool {
		if result.Findings[i].Level != result.Findings[j].Level {
			return levelRank(result.Findings[i].Level) > levelRank(result.Findings[j].Level)
		}
		return result.Findings[i].ID < result.Findings[j].ID
	})
	return result, ctx.Err()
}

func (s *linuxScanner) scanSystemd(ctx context.Context, result *Result) {
	roots := []systemdRoot{
		{path: "/etc/systemd/system.control", source: "local system control", scope: "system", user: "root", reason: "unit is present in systemd's highest-priority persistent control directory"},
		{path: "/run/systemd/system.control", source: "runtime system control", scope: "system", user: "root", reason: "unit is present in systemd's highest-priority runtime control directory", generated: true},
		{path: "/etc/systemd/system", source: "local system", scope: "system", user: "root", reason: "unit is present in the administrator system unit directory"},
		{path: "/etc/systemd/system.attached", source: "attached system", scope: "system", user: "root", reason: "unit is attached to the persistent system manager configuration"},
		{path: "/run/systemd/transient", source: "transient", scope: "system", user: "root", reason: "unit was created in systemd's transient runtime directory", generated: true},
		{path: "/run/systemd/generator.early", source: "generated", scope: "system", user: "root", reason: "unit was produced by a systemd generator", generated: true},
		{path: "/run/systemd/system", source: "runtime", scope: "system", user: "root", reason: "unit is present in the runtime system unit directory", generated: true},
		{path: "/run/systemd/system.attached", source: "attached runtime system", scope: "system", user: "root", reason: "unit is attached to the runtime system manager configuration", generated: true},
		{path: "/run/systemd/generator", source: "generated", scope: "system", user: "root", reason: "unit was produced by a systemd generator", generated: true},
		{path: "/run/systemd/generator.late", source: "generated", scope: "system", user: "root", reason: "unit was produced by a systemd generator", generated: true},
		{path: "/usr/local/lib/systemd/system", source: "local system", scope: "system", user: "root", reason: "unit is installed outside the distribution vendor directory"},
		{path: "/usr/lib/systemd/system", source: "vendor system", scope: "system", user: "root", reason: "unit is installed in the distribution vendor directory"},
		{path: "/lib/systemd/system", source: "vendor system", scope: "system", user: "root", reason: "unit is installed in the distribution vendor directory"},
		{path: "/etc/systemd/user.control", source: "local user control", scope: "user", user: "system users", reason: "unit is present in the highest-priority persistent user control directory"},
		{path: "/etc/xdg/systemd/user", source: "local user", scope: "user", user: "system users", reason: "unit is configured in the system XDG user configuration directory"},
		{path: "/etc/systemd/user", source: "local user", scope: "user", user: "system users", reason: "unit is configured for user sessions by an administrator"},
		{path: "/etc/systemd/user.attached", source: "attached user", scope: "user", user: "system users", reason: "unit is attached to the persistent user manager configuration"},
		{path: "/run/systemd/user.control", source: "runtime user control", scope: "user", user: "system users", reason: "unit is present in the highest-priority runtime user control directory", generated: true},
		{path: "/run/systemd/user", source: "runtime user", scope: "user", user: "system users", reason: "unit is present in the runtime user unit directory", generated: true},
		{path: "/run/systemd/user.attached", source: "attached runtime user", scope: "user", user: "system users", reason: "unit is attached to the runtime user manager configuration", generated: true},
		{path: "/usr/local/lib/systemd/user", source: "local user", scope: "user", user: "system users", reason: "user unit is installed outside the distribution vendor directory"},
		{path: "/usr/lib/systemd/user", source: "vendor user", scope: "user", user: "system users", reason: "user unit is installed in the distribution vendor directory"},
		{path: "/lib/systemd/user", source: "vendor user", scope: "user", user: "system users", reason: "user unit is installed in the distribution vendor directory"},
		{path: "/usr/local/share/systemd/user", source: "local user data", scope: "user", user: "system users", reason: "user unit is installed in the local XDG data directory"},
		{path: "/usr/share/systemd/user", source: "vendor user data", scope: "user", user: "system users", reason: "user unit is installed in the distribution XDG data directory"},
	}
	if s.home != "" {
		roots = append(roots,
			systemdRoot{path: filepath.Join(s.home, ".config/systemd/user.control"), source: "local user control", scope: "user", user: s.currentUser, reason: "unit is configured in the current user's highest-priority control directory"},
			systemdRoot{path: filepath.Join(s.home, ".config/systemd/user"), source: "local user", scope: "user", user: s.currentUser, reason: "unit is configured in the current user's home directory"},
			systemdRoot{path: filepath.Join(s.home, ".local/share/systemd/user"), source: "local user data", scope: "user", user: s.currentUser, reason: "unit is installed in the current user's local data directory"},
		)
	}
	if path := os.Getenv("XDG_CONFIG_HOME"); path != "" {
		roots = append(roots, systemdRoot{path: filepath.Join(path, "systemd/user"), source: "local user", scope: "user", user: s.currentUser, reason: "unit is configured through XDG_CONFIG_HOME"})
	}
	if path := os.Getenv("XDG_DATA_HOME"); path != "" {
		roots = append(roots, systemdRoot{path: filepath.Join(path, "systemd/user"), source: "local user data", scope: "user", user: s.currentUser, reason: "unit is installed through XDG_DATA_HOME"})
	}
	if path := os.Getenv("XDG_RUNTIME_DIR"); path != "" {
		for _, directory := range []string{"user.control", "transient", "user", "generator.early", "generator", "generator.late"} {
			roots = append(roots, systemdRoot{path: filepath.Join(path, "systemd", directory), source: "runtime user", scope: "user", user: s.currentUser, reason: "unit is present in the current user's XDG runtime directory", generated: true})
		}
	}
	roots = append(roots, userHomeSystemdRoots("/etc/passwd")...)
	roots = append(roots, runtimeUserSystemdRoots("/run/user")...)
	enabled := discoverEnabledUnits(ctx, roots, result)
	seenRoots := make(map[string]struct{})

	for _, item := range roots {
		if ctx.Err() != nil {
			return
		}
		if _, err := os.Stat(item.path); err != nil {
			if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
				result.Warnings = append(result.Warnings, fmt.Sprintf("cannot inspect %s: %v", item.path, err))
			}
			continue
		}
		canonicalRoot, err := filepath.EvalSymlinks(item.path)
		if err == nil {
			if _, duplicate := seenRoots[canonicalRoot]; duplicate {
				continue
			}
			seenRoots[canonicalRoot] = struct{}{}
		}
		err = filepath.WalkDir(item.path, func(path string, entry fs.DirEntry, walkErr error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if walkErr != nil {
				if errors.Is(walkErr, os.ErrPermission) {
					result.Warnings = append(result.Warnings, fmt.Sprintf("permission denied: %s", path))
					return nil
				}
				return walkErr
			}
			if entry.IsDir() {
				if path != item.path && (strings.HasSuffix(entry.Name(), ".wants") || strings.HasSuffix(entry.Name(), ".requires") || strings.HasSuffix(entry.Name(), ".upholds")) {
					return filepath.SkipDir
				}
				return nil
			}
			if !isUnitFile(path) {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("cannot read %s: %v", path, err))
				return nil
			}
			details := parseUnit(string(data))
			command := strings.Join(details.commands, "; ")
			level, commandReason := classifyCommand(command)
			reason := item.reason
			if commandReason != "" {
				reason += "; " + commandReason
			}
			unitUser := details.user
			if unitUser == "" {
				unitUser = item.user
			}
			relative, _ := filepath.Rel(item.path, path)
			unit := unitName(relative)
			role := "definition"
			if filepath.Ext(path) == ".conf" {
				role = "drop-in"
			} else if strings.TrimSpace(string(data)) == "" {
				role = "mask"
			}
			resolvedPath := ""
			if entry.Type()&os.ModeSymlink != 0 {
				resolvedPath, _ = filepath.EvalSymlinks(path)
				if resolvedPath == "/dev/null" {
					role = "mask"
				}
			}
			enablement := "not linked"
			if enabled[item.scope+"|"+unit] {
				enablement = "linked"
			}
			if role == "mask" {
				enablement = "masked"
			}
			finding := Finding{
				ID:             "systemd|" + path,
				Level:          level,
				Mechanism:      mechanismFromPath(path),
				Name:           relative,
				Path:           path,
				User:           unitUser,
				Command:        command,
				Schedule:       strings.Join(details.schedule, "; "),
				Source:         item.source,
				Scope:          item.scope,
				Unit:           unit,
				Role:           role,
				Enablement:     enablement,
				ResolvedPath:   resolvedPath,
				Reason:         reason,
				Recommendation: recommendation(level),
			}
			s.applyVerification(&finding, path, item.generated)
			s.applyReferencedVerification(&finding, details.executables)
			result.Findings = append(result.Findings, finding)
			return nil
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			result.Warnings = append(result.Warnings, fmt.Sprintf("scan %s: %v", item.path, err))
		}
	}
	classifySystemdRoles(result.Findings)
}

func (s *linuxScanner) scanCron(ctx context.Context, result *Result) {
	type cronTarget struct {
		path       string
		source     string
		systemFile bool
		user       string
		periodic   bool
		anacron    bool
		strictName bool
		level      Level
	}
	targets := []cronTarget{
		{path: "/etc/crontab", source: "system cron", systemFile: true, level: LevelInfo},
		{path: "/etc/anacrontab", source: "system anacron", user: "root", anacron: true, level: LevelInfo},
		{path: "/etc/cron.d", source: "system cron", systemFile: true, strictName: true, level: LevelInfo},
		{path: "/var/spool/cron", source: "user crontab", user: "file owner", level: LevelReview},
		{path: "/etc/cron.hourly", source: "periodic cron", user: "root", periodic: true, strictName: true, level: LevelInfo},
		{path: "/etc/cron.daily", source: "periodic cron", user: "root", periodic: true, strictName: true, level: LevelInfo},
		{path: "/etc/cron.weekly", source: "periodic cron", user: "root", periodic: true, strictName: true, level: LevelInfo},
		{path: "/etc/cron.monthly", source: "periodic cron", user: "root", periodic: true, strictName: true, level: LevelInfo},
	}
	for _, target := range targets {
		if ctx.Err() != nil {
			return
		}
		info, err := os.Stat(target.path)
		if err != nil {
			if errors.Is(err, os.ErrPermission) {
				result.Warnings = append(result.Warnings, fmt.Sprintf("permission denied: %s", target.path))
			}
			continue
		}
		paths := []string{target.path}
		if info.IsDir() {
			paths = paths[:0]
			walkErr := filepath.WalkDir(target.path, func(path string, entry fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					if errors.Is(walkErr, os.ErrPermission) {
						result.Warnings = append(result.Warnings, fmt.Sprintf("permission denied: %s", path))
						return nil
					}
					return walkErr
				}
				if !entry.IsDir() {
					paths = append(paths, path)
				}
				return nil
			})
			if walkErr != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("scan cron directory %s: %v", target.path, walkErr))
			}
		}
		for _, path := range paths {
			if ctx.Err() != nil {
				return
			}
			eligible, eligibilityReason := cronFileEligibility(path, target.periodic, target.strictName)
			if target.periodic {
				level, commandReason := classifyCommand(path)
				if level != LevelWarning {
					level = target.level
				}
				reason := "script is present in a periodic cron directory; file eligibility and package provenance are reported separately"
				role := "eligible script"
				enablement := "eligible"
				if !eligible {
					role = "ignored candidate"
					enablement = "not eligible"
					reason = appendReason(reason, eligibilityReason)
				}
				if commandReason != "" {
					reason += "; " + commandReason
				}
				finding := Finding{
					ID:             "cron|" + path,
					Level:          level,
					Mechanism:      "periodic cron",
					Name:           filepath.Base(path),
					Path:           path,
					User:           target.user,
					Command:        path,
					Source:         target.source,
					Role:           role,
					Enablement:     enablement,
					Reason:         reason,
					Recommendation: recommendation(level),
				}
				s.applyVerification(&finding, path, false)
				s.applyReferencedVerification(&finding, []string{path})
				result.Findings = append(result.Findings, finding)
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("cannot read %s: %v", path, err))
				continue
			}
			if len(data) > 0 && data[len(data)-1] != '\n' {
				eligible = false
				eligibilityReason = appendReason(eligibilityReason, "file does not end with a newline")
			}
			entries := parseCron(string(data), target.systemFile)
			if target.anacron {
				entries = parseAnacron(string(data))
			}
			for _, entry := range entries {
				level, commandReason := classifyCommand(entry.command)
				if level != LevelWarning {
					level = target.level
				}
				reason := "scheduled command discovered in cron configuration"
				if target.source == "user crontab" {
					reason = "command is configured in a user crontab"
				}
				if commandReason != "" {
					reason += "; " + commandReason
				}
				role := "eligible entry"
				enablement := "eligible"
				if !eligible {
					role = "ignored candidate"
					enablement = "not eligible"
					reason = appendReason(reason, eligibilityReason)
				}
				entryUser := entry.user
				if entryUser == "" {
					entryUser = target.user
					if target.source == "user crontab" {
						entryUser = filepath.Base(path)
					}
				}
				mechanism := "cron entry"
				if target.anacron {
					mechanism = "anacron entry"
				}
				finding := Finding{
					ID:             fmt.Sprintf("cron|%s|%d", path, entry.line),
					Level:          level,
					Mechanism:      mechanism,
					Name:           fmt.Sprintf("%s:%d", filepath.Base(path), entry.line),
					Path:           path,
					User:           entryUser,
					Command:        entry.command,
					Schedule:       entry.schedule,
					Source:         target.source,
					Role:           role,
					Enablement:     enablement,
					Reason:         reason,
					Recommendation: recommendation(level),
				}
				s.applyVerification(&finding, path, false)
				s.applyReferencedVerification(&finding, []string{commandExecutable(entry.command)})
				result.Findings = append(result.Findings, finding)
			}
		}
	}
}

func cronFileEligibility(path string, executable, strictName bool) (bool, string) {
	if strictName && !validCronName(filepath.Base(path)) {
		return false, "filename contains characters ignored by common cron/run-parts implementations"
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, "file target is missing or unreadable"
	}
	if !info.Mode().IsRegular() {
		return false, "path does not resolve to a regular file"
	}
	if info.Mode().Perm()&0o022 != 0 {
		return false, "file is writable by group or other users"
	}
	if executable && info.Mode().Perm()&0o111 == 0 {
		return false, "periodic script is not executable"
	}
	return true, ""
}

func validCronName(name string) bool {
	if name == "" || strings.HasPrefix(name, ".") {
		return false
	}
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func (s *linuxScanner) applyVerification(finding *Finding, path string, generated bool) {
	if generated {
		finding.Provenance = ProvenanceGenerated
		finding.Integrity = "runtime-generated content has no persistent package digest"
		if finding.Level != LevelWarning {
			finding.Level = LevelReview
		}
		finding.Reason = appendReason(finding.Reason, finding.Integrity)
		finding.Recommendation = recommendation(finding.Level)
		return
	}
	verifier := s.verifier
	if verifier == nil {
		verifier = unknownVerifier{detail: "package verification was not initialized"}
	}
	verified := verifier.Verify(path)
	finding.Provenance = verified.provenance
	finding.Package = verified.packageName
	finding.PackageManager = verified.manager
	finding.Integrity = verified.detail
	finding.Reason = appendReason(finding.Reason, verified.detail)
	if finding.Level != LevelWarning {
		switch verified.provenance {
		case ProvenancePackageMatch:
			finding.Level = LevelInfo
		default:
			finding.Level = LevelReview
		}
	}
	finding.Recommendation = recommendation(finding.Level)
}

func (s *linuxScanner) applyReferencedVerification(finding *Finding, paths []string) {
	if s.verifier == nil {
		return
	}
	seen := make(map[string]struct{})
	for _, path := range paths {
		if path == "" || path == finding.Path {
			continue
		}
		path = filepath.Clean(path)
		if _, exists := seen[path]; exists {
			continue
		}
		seen[path] = struct{}{}
		verified := s.verifier.Verify(path)
		finding.ReferencedFiles = append(finding.ReferencedFiles, FileEvidence{
			Path:           path,
			Provenance:     verified.provenance,
			Package:        verified.packageName,
			PackageManager: verified.manager,
			Integrity:      verified.detail,
		})
		switch verified.provenance {
		case ProvenancePackageModified:
			finding.Provenance = ProvenancePackageModified
			finding.Level = maxLevel(finding.Level, LevelReview)
			finding.Reason = appendReason(finding.Reason, "referenced executable differs from package metadata: "+path)
		case ProvenanceLocal:
			if finding.Provenance == ProvenancePackageMatch {
				finding.Provenance = ProvenanceLocal
			}
			finding.Level = maxLevel(finding.Level, LevelReview)
			finding.Reason = appendReason(finding.Reason, "referenced executable is not package-owned: "+path)
		case ProvenanceUnverified:
			if finding.Provenance == ProvenancePackageMatch {
				finding.Provenance = ProvenanceUnverified
			}
			finding.Level = maxLevel(finding.Level, LevelReview)
		case ProvenancePackageOwned:
			if finding.Provenance == ProvenancePackageMatch {
				finding.Provenance = ProvenancePackageOwned
			}
		}
	}
	finding.Recommendation = recommendation(finding.Level)
}

func maxLevel(left, right Level) Level {
	if levelRank(right) > levelRank(left) {
		return right
	}
	return left
}

func discoverEnabledUnits(ctx context.Context, roots []systemdRoot, result *Result) map[string]bool {
	enabled := make(map[string]bool)
	for _, root := range roots {
		if ctx.Err() != nil {
			break
		}
		if _, err := os.Stat(root.path); err != nil {
			continue
		}
		err := filepath.WalkDir(root.path, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			parent := filepath.Base(filepath.Dir(path))
			if strings.HasSuffix(parent, ".wants") || strings.HasSuffix(parent, ".requires") || strings.HasSuffix(parent, ".upholds") {
				enabled[root.scope+"|"+entry.Name()] = true
			}
			return nil
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			result.Warnings = append(result.Warnings, fmt.Sprintf("inspect systemd enablement under %s: %v", root.path, err))
		}
	}
	return enabled
}

func classifySystemdRoles(findings []Finding) {
	definitions := make(map[string][]int)
	dropIns := make(map[string][]int)
	for index := range findings {
		finding := &findings[index]
		if finding.Unit == "" || !strings.HasPrefix(finding.Mechanism, "systemd") {
			continue
		}
		key := finding.Scope + "|" + finding.Unit
		if finding.Role == "drop-in" {
			dropIns[key] = append(dropIns[key], index)
			continue
		}
		definitions[key] = append(definitions[key], index)
	}
	for key, indexes := range definitions {
		sort.Slice(indexes, func(i, j int) bool {
			left := systemdPriority(findings[indexes[i]].Path)
			right := systemdPriority(findings[indexes[j]].Path)
			if left == right {
				return findings[indexes[i]].Path < findings[indexes[j]].Path
			}
			return left < right
		})
		effective := &findings[indexes[0]]
		if effective.Role == "mask" {
			effective.Role = "effective mask"
		} else {
			effective.Role = "effective"
		}
		for _, index := range indexes[1:] {
			findings[index].Role = "shadowed"
			effective.RelatedPaths = append(effective.RelatedPaths, findings[index].Path)
		}
		for _, index := range dropIns[key] {
			dropIn := findings[index]
			effective.RelatedPaths = append(effective.RelatedPaths, dropIn.Path)
			switch dropIn.Provenance {
			case ProvenanceLocal, ProvenancePackageModified:
				if effective.Provenance == ProvenancePackageMatch || effective.Provenance == ProvenancePackageOwned {
					effective.Provenance = ProvenancePackageModified
				}
				effective.Integrity = appendReason(effective.Integrity, "effective configuration includes a local or modified drop-in: "+dropIn.Path)
				effective.Reason = appendReason(effective.Reason, "effective unit configuration is changed by "+dropIn.Path)
				if effective.Level == LevelInfo {
					effective.Level = LevelReview
				}
			case ProvenanceUnverified:
				if effective.Provenance == ProvenancePackageMatch {
					effective.Provenance = ProvenanceUnverified
				}
			}
		}
		sort.Strings(effective.RelatedPaths)
		effective.Recommendation = recommendation(effective.Level)
	}
}

func unitName(relative string) string {
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) > 1 && strings.HasSuffix(parts[0], ".d") {
		return strings.TrimSuffix(parts[0], ".d")
	}
	return filepath.Base(relative)
}

func systemdPriority(path string) int {
	clean := filepath.Clean(path)
	switch {
	case strings.Contains(clean, "/.config/systemd/user.control/"):
		return 0
	case strings.Contains(clean, "/.config/systemd/user/"):
		return 5
	case strings.Contains(clean, "/systemd/user.control/"):
		return 15
	case strings.Contains(clean, "/systemd/transient/"):
		return 20
	case strings.Contains(clean, "/systemd/generator.early/"):
		return 25
	case strings.HasPrefix(clean, "/etc/systemd/system.control/") || strings.HasPrefix(clean, "/etc/systemd/user.control/"):
		return 10
	case strings.HasPrefix(clean, "/run/systemd/system.control/") || strings.HasPrefix(clean, "/run/systemd/user.control/"):
		return 15
	case strings.HasPrefix(clean, "/run/systemd/transient/"):
		return 20
	case strings.HasPrefix(clean, "/run/systemd/generator.early/"):
		return 25
	case strings.Contains(clean, "/systemd/system.attached/") || strings.Contains(clean, "/systemd/user.attached/"):
		return 35
	case strings.HasPrefix(clean, "/etc/systemd/"):
		return 30
	case strings.HasPrefix(clean, "/run/systemd/system/") || strings.HasPrefix(clean, "/run/systemd/user/"):
		return 40
	case strings.HasPrefix(clean, "/run/user/") && strings.Contains(clean, "/systemd/user/"):
		return 40
	case strings.HasPrefix(clean, "/run/systemd/generator/"):
		return 50
	case strings.Contains(clean, "/systemd/generator/"):
		return 50
	case strings.HasPrefix(clean, "/usr/local/lib/systemd/"):
		return 60
	case strings.Contains(clean, "/.local/share/systemd/user/") || strings.HasPrefix(clean, "/usr/local/share/systemd/user/"):
		return 65
	case strings.HasPrefix(clean, "/usr/lib/systemd/"):
		return 70
	case strings.HasPrefix(clean, "/usr/share/systemd/user/"):
		return 75
	case strings.HasPrefix(clean, "/lib/systemd/"):
		return 80
	case strings.HasPrefix(clean, "/run/systemd/generator.late/"):
		return 90
	default:
		return 100
	}
}

func userHomeSystemdRoots(passwdPath string) []systemdRoot {
	file, err := os.Open(passwdPath)
	if err != nil {
		return nil
	}
	defer file.Close()
	roots := make([]systemdRoot, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 6 || fields[0] == "" || fields[5] == "" || fields[5] == "/" {
			continue
		}
		for _, relative := range []string{".config/systemd/user.control", ".config/systemd/user", ".local/share/systemd/user"} {
			roots = append(roots, systemdRoot{
				path:   filepath.Join(fields[5], relative),
				source: "local user",
				scope:  "user",
				user:   fields[0],
				reason: "unit is configured in a local user unit directory",
			})
		}
	}
	return roots
}

func runtimeUserSystemdRoots(runtimeRoot string) []systemdRoot {
	entries, err := os.ReadDir(runtimeRoot)
	if err != nil {
		return nil
	}
	roots := make([]systemdRoot, 0)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		for _, directory := range []string{"user.control", "transient", "user", "generator.early", "generator", "generator.late"} {
			roots = append(roots, systemdRoot{
				path:      filepath.Join(runtimeRoot, entry.Name(), "systemd", directory),
				source:    "runtime user",
				scope:     "user",
				user:      entry.Name(),
				reason:    "unit is present in a user's XDG runtime directory",
				generated: true,
			})
		}
	}
	return roots
}

func appendReason(existing, addition string) string {
	if existing == "" {
		return addition
	}
	if addition == "" || strings.Contains(existing, addition) {
		return existing
	}
	return existing + "; " + addition
}

func isUnitFile(path string) bool {
	switch filepath.Ext(path) {
	case ".service", ".timer", ".socket", ".path", ".mount", ".automount", ".swap", ".conf":
		return true
	default:
		return false
	}
}

func recommendation(level Level) string {
	if level == LevelWarning {
		return "Inspect the executable, file ownership, package source, timestamps, and related network activity."
	}
	return "Verify that the entry has an expected owner, source, command, and business purpose."
}

func levelRank(level Level) int {
	switch level {
	case LevelWarning:
		return 3
	case LevelReview:
		return 2
	default:
		return 1
	}
}
