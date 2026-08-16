package main

import (
	"bufio"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xhzeem/procwire/integration/fixture"
)

type options struct {
	duration            time.Duration
	activityDelay       time.Duration
	manifestPath        string
	fixtureRoot         string
	modifiedPackageFile string
	dnsNames            []string
	tcpListeners        int
	udpListeners        int
}

type tcpFixture struct {
	listener net.Listener
	port     uint16
}

type udpFixture struct {
	connection net.PacketConn
	port       uint16
}

func main() {
	options := parseFlags()
	if err := run(options); err != nil {
		fmt.Fprintln(os.Stderr, "trafficgen:", err)
		os.Exit(1)
	}
}

func parseFlags() options {
	duration := flag.Duration("duration", 10*time.Second, "traffic generation duration")
	activityDelay := flag.Duration("activity-delay", 0, "delay traffic churn after publishing the fixture manifest")
	manifestPath := flag.String("manifest", "", "write generated fixture expectations as JSON")
	fixtureRoot := flag.String("fixture-root", "", "install randomized persistence fixtures below this root")
	modifiedPackageFile := flag.String("modify-package-file", "", "package-owned file to modify below the fixture root")
	dnsNames := flag.String("dns-names", "example.com,example.net,iana.org", "comma-separated DNS names to rotate")
	tcpListeners := flag.Int("tcp-listeners", 4, "number of random TCP listening ports")
	udpListeners := flag.Int("udp-listeners", 3, "number of random UDP listening ports")
	flag.Parse()
	names := make([]string, 0)
	for _, name := range strings.Split(*dnsNames, ",") {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	return options{
		duration:            *duration,
		activityDelay:       *activityDelay,
		manifestPath:        *manifestPath,
		fixtureRoot:         *fixtureRoot,
		modifiedPackageFile: *modifiedPackageFile,
		dnsNames:            names,
		tcpListeners:        *tcpListeners,
		udpListeners:        *udpListeners,
	}
}

func run(options options) error {
	if options.duration <= 0 {
		return errors.New("duration must be positive")
	}
	if options.activityDelay < 0 {
		return errors.New("activity delay cannot be negative")
	}
	if options.tcpListeners < 1 || options.udpListeners < 1 {
		return errors.New("listener counts must be positive")
	}
	if len(options.dnsNames) == 0 {
		return errors.New("at least one DNS name is required")
	}

	tcpFixtures, err := openTCPFixtures(options.tcpListeners)
	if err != nil {
		return err
	}
	defer closeTCPFixtures(tcpFixtures)
	udpFixtures, err := openUDPFixtures(options.udpListeners)
	if err != nil {
		return err
	}
	defer closeUDPFixtures(udpFixtures)

	for _, item := range tcpFixtures {
		go serveTCP(item.listener)
	}
	for _, item := range udpFixtures {
		go drainUDP(item.connection)
	}

	persistentClients := make([]net.Conn, 0, len(tcpFixtures))
	for _, item := range tcpFixtures {
		connection, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", item.port))
		if err != nil {
			return fmt.Errorf("dial generated TCP listener: %w", err)
		}
		persistentClients = append(persistentClients, connection)
	}
	defer func() {
		for _, connection := range persistentClients {
			_ = connection.Close()
		}
	}()
	dnsConnection, err := net.DialTimeout("udp", net.JoinHostPort(dnsServer(), "53"), time.Second)
	if err != nil {
		return fmt.Errorf("open persistent DNS socket: %w", err)
	}
	defer dnsConnection.Close()

	manifest := fixture.Manifest{
		GeneratedAt: time.Now(),
		ProcessName: processName(),
		DNSNames:    append([]string(nil), options.dnsNames...),
	}
	for _, item := range tcpFixtures {
		manifest.TCPPorts = append(manifest.TCPPorts, item.port)
	}
	for _, item := range udpFixtures {
		manifest.UDPPorts = append(manifest.UDPPorts, item.port)
	}
	if options.fixtureRoot != "" {
		if err := installPersistenceFixtures(options, &manifest); err != nil {
			return err
		}
	}
	if options.manifestPath != "" {
		if err := writeManifest(options.manifestPath, manifest); err != nil {
			return err
		}
	}
	if options.activityDelay > 0 {
		time.Sleep(options.activityDelay)
	}

	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	activityTicker := time.NewTicker(70 * time.Millisecond)
	dnsTicker := time.NewTicker(180 * time.Millisecond)
	transientTicker := time.NewTicker(550 * time.Millisecond)
	timer := time.NewTimer(options.duration)
	defer activityTicker.Stop()
	defer dnsTicker.Stop()
	defer transientTicker.Stop()
	defer timer.Stop()

	sequence := uint16(random.Intn(1 << 16))
	dnsIndex := 0
	for {
		select {
		case <-activityTicker.C:
			if random.Intn(2) == 0 {
				item := tcpFixtures[random.Intn(len(tcpFixtures))]
				go churnTCP(item.port, time.Duration(40+random.Intn(500))*time.Millisecond)
			} else {
				item := udpFixtures[random.Intn(len(udpFixtures))]
				go sendUDP(item.port, sequence)
			}
			sequence++
		case <-dnsTicker.C:
			name := options.dnsNames[dnsIndex%len(options.dnsNames)]
			dnsIndex++
			_, _ = dnsConnection.Write(dnsQuery(name, sequence))
			if dnsIndex%3 == 0 {
				go sendDNS(name, sequence+1)
			}
			sequence++
		case <-transientTicker.C:
			go transientTCPActivity(time.Duration(150+random.Intn(500)) * time.Millisecond)
		case <-timer.C:
			return nil
		}
	}
}

func openTCPFixtures(count int) ([]tcpFixture, error) {
	fixtures := make([]tcpFixture, 0, count)
	for range count {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			closeTCPFixtures(fixtures)
			return nil, fmt.Errorf("open random TCP listener: %w", err)
		}
		fixtures = append(fixtures, tcpFixture{
			listener: listener,
			port:     uint16(listener.Addr().(*net.TCPAddr).Port),
		})
	}
	return fixtures, nil
}

func openUDPFixtures(count int) ([]udpFixture, error) {
	fixtures := make([]udpFixture, 0, count)
	for range count {
		connection, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			closeUDPFixtures(fixtures)
			return nil, fmt.Errorf("open random UDP listener: %w", err)
		}
		fixtures = append(fixtures, udpFixture{
			connection: connection,
			port:       uint16(connection.LocalAddr().(*net.UDPAddr).Port),
		})
	}
	return fixtures, nil
}

func closeTCPFixtures(fixtures []tcpFixture) {
	for _, item := range fixtures {
		_ = item.listener.Close()
	}
}

func closeUDPFixtures(fixtures []udpFixture) {
	for _, item := range fixtures {
		_ = item.connection.Close()
	}
}

func serveTCP(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer connection.Close()
			_, _ = io.Copy(io.Discard, connection)
		}()
	}
}

func drainUDP(connection net.PacketConn) {
	buffer := make([]byte, 2048)
	for {
		if _, _, err := connection.ReadFrom(buffer); err != nil {
			return
		}
	}
}

func churnTCP(port uint16, hold time.Duration) {
	connection, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(connection, "procwire tcp fixture %d", time.Now().UnixNano())
	time.Sleep(hold)
	_ = connection.Close()
}

func sendUDP(port, sequence uint16) {
	connection, err := net.Dial("udp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return
	}
	defer connection.Close()
	_, _ = fmt.Fprintf(connection, "procwire udp fixture %d", sequence)
}

func transientTCPActivity(hold time.Duration) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return
	}
	defer listener.Close()
	go serveTCP(listener)
	connection, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		return
	}
	time.Sleep(hold)
	_ = connection.Close()
}

func sendDNS(name string, transactionID uint16) {
	connection, err := net.DialTimeout("udp", net.JoinHostPort(dnsServer(), "53"), time.Second)
	if err != nil {
		return
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := connection.Write(dnsQuery(name, transactionID)); err != nil {
		return
	}
	buffer := make([]byte, 2048)
	_, _ = connection.Read(buffer)
}

func dnsServer() string {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "127.0.0.11"
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == "nameserver" {
			return strings.Trim(fields[1], "[]")
		}
	}
	return "127.0.0.11"
}

func dnsQuery(name string, transactionID uint16) []byte {
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], transactionID)
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	return append(query, 0, 0, 1, 0, 1)
}

func installPersistenceFixtures(options options, manifest *fixture.Manifest) error {
	suffix := randomSuffix()
	base := "procwire-it-" + suffix
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve traffic generator executable: %w", err)
	}
	manifest.ServiceUnits = []string{base + "-beacon.service", base + "-worker.service"}
	manifest.TimerUnits = []string{base + "-beacon.timer", base + "-worker.timer"}
	manifest.CronPaths = []string{"/etc/cron.d/" + base, "/etc/cron.hourly/" + base}

	for index, unit := range manifest.ServiceUnits {
		contents := fmt.Sprintf("[Unit]\nDescription=ProcWire randomized integration service %d\n[Service]\nType=oneshot\nExecStart=%s --duration 1s\n", index+1, executable)
		if err := writeFixture(options.fixtureRoot, "/etc/systemd/system/"+unit, []byte(contents), 0o644); err != nil {
			return err
		}
	}
	for index, unit := range manifest.TimerUnits {
		contents := fmt.Sprintf("[Unit]\nDescription=ProcWire randomized integration timer %d\n[Timer]\nOnBootSec=%ds\nOnUnitActiveSec=%dm\nUnit=%s\n[Install]\nWantedBy=timers.target\n", index+1, 20+index*15, 3+index, manifest.ServiceUnits[index])
		if err := writeFixture(options.fixtureRoot, "/etc/systemd/system/"+unit, []byte(contents), 0o644); err != nil {
			return err
		}
		if err := enableUnit(options.fixtureRoot, "timers.target.wants", unit); err != nil {
			return err
		}
	}
	cronLine := fmt.Sprintf("*/3 * * * * root %s --duration 1s\n", executable)
	if err := writeFixture(options.fixtureRoot, manifest.CronPaths[0], []byte(cronLine), 0o644); err != nil {
		return err
	}
	hourly := fmt.Sprintf("#!/bin/sh\n%s --duration 1s\n", executable)
	if err := writeFixture(options.fixtureRoot, manifest.CronPaths[1], []byte(hourly), 0o755); err != nil {
		return err
	}
	if options.modifiedPackageFile != "" {
		path := rootedPath(options.fixtureRoot, options.modifiedPackageFile)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return fmt.Errorf("open package fixture %s: %w", path, err)
		}
		_, writeErr := fmt.Fprintf(file, "\n# ProcWire randomized integration change %s\n", suffix)
		closeErr := file.Close()
		if writeErr != nil {
			return fmt.Errorf("modify package fixture %s: %w", path, writeErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close package fixture %s: %w", path, closeErr)
		}
		manifest.ModifiedPackageFile = canonicalFixturePath(options.fixtureRoot, path, options.modifiedPackageFile)
	}
	return nil
}

func writeFixture(root, path string, contents []byte, mode os.FileMode) error {
	target := rootedPath(root, path)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create fixture directory: %w", err)
	}
	if err := os.WriteFile(target, contents, mode); err != nil {
		return fmt.Errorf("write fixture %s: %w", target, err)
	}
	return nil
}

func enableUnit(root, target, unit string) error {
	directory := rootedPath(root, "/etc/systemd/system/"+target)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create unit target directory: %w", err)
	}
	linkPath := filepath.Join(directory, unit)
	if err := os.Symlink("../"+unit, linkPath); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("enable fixture unit %s: %w", unit, err)
	}
	return nil
}

func rootedPath(root, path string) string {
	clean := filepath.Clean(string(filepath.Separator) + path)
	return filepath.Join(root, strings.TrimPrefix(clean, string(filepath.Separator)))
}

func canonicalFixturePath(root, target, fallback string) string {
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return filepath.Clean(fallback)
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return filepath.Clean(fallback)
	}
	if resolvedRoot, resolveErr := filepath.EvalSymlinks(absoluteRoot); resolveErr == nil {
		absoluteRoot = resolvedRoot
	}
	relative, err := filepath.Rel(absoluteRoot, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return filepath.Clean(fallback)
	}
	return string(filepath.Separator) + filepath.ToSlash(relative)
}

func writeManifest(path string, manifest fixture.Manifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode fixture manifest: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create manifest directory: %w", err)
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write fixture manifest: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("publish fixture manifest: %w", err)
	}
	return nil
}

func randomSuffix() string {
	value := make([]byte, 5)
	if _, err := cryptorand.Read(value); err == nil {
		return hex.EncodeToString(value)
	}
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

func processName() string {
	executable, err := os.Executable()
	if err != nil {
		return ""
	}
	name := filepath.Base(executable)
	if len(name) > 15 {
		name = name[:15]
	}
	return name
}
