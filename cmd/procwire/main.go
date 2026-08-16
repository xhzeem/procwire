package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/xhzeem/procwire/internal/dnsmon"
	"github.com/xhzeem/procwire/internal/observe"
	"github.com/xhzeem/procwire/internal/persistence"
	"github.com/xhzeem/procwire/internal/report"
	"github.com/xhzeem/procwire/internal/tui"
)

var version = "dev"

type options struct {
	interval  time.Duration
	duration  time.Duration
	output    string
	noReport  bool
	showBuild bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "procwire:", err)
		os.Exit(1)
	}
}

func run() (returnErr error) {
	options := parseFlags()
	if options.showBuild {
		fmt.Printf("ProcWire %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return nil
	}
	if options.interval < 100*time.Millisecond {
		return fmt.Errorf("interval must be at least 100ms")
	}

	var recorder *report.Writer
	var err error
	if !options.noReport {
		if options.output != "" {
			recorder, err = report.Open(options.output)
		} else {
			workingDirectory, getwdErr := os.Getwd()
			if getwdErr != nil {
				return fmt.Errorf("get launch directory: %w", getwdErr)
			}
			recorder, err = report.OpenDefault(workingDirectory, time.Now())
		}
		if err != nil {
			return err
		}
		defer func() {
			if err := recorder.Close(); err != nil && returnErr == nil {
				returnErr = err
			}
		}()
	}

	reportPath := ""
	if recorder != nil {
		reportPath = recorder.Path()
		hostname, _ := os.Hostname()
		if err := recorder.Record("session_start", map[string]any{
			"version":          version,
			"hostname":         hostname,
			"os":               runtime.GOOS,
			"architecture":     runtime.GOARCH,
			"polling_interval": options.interval.String(),
		}); err != nil {
			return err
		}
	}

	dnsMonitor := dnsmon.NewMonitor()
	dnsErr := dnsMonitor.Start()
	defer func() {
		if err := dnsMonitor.Close(); err != nil && returnErr == nil {
			returnErr = fmt.Errorf("close DNS monitor: %w", err)
		}
	}()
	if recorder != nil {
		if err := recorder.Record("dns_monitor_status", map[string]any{
			"active": dnsErr == nil,
			"error":  errorText(dnsErr),
		}); err != nil {
			return err
		}
	}

	model := tui.New(tui.Config{
		Collector:  observe.NewCollector(),
		DNSMonitor: dnsMonitor,
		DNSError:   dnsErr,
		Scanner:    persistence.NewScanner(),
		Recorder:   optionalRecorder(recorder),
		ReportPath: reportPath,
		Interval:   options.interval,
		RunFor:     options.duration,
		Version:    version,
	})
	program := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := program.Run(); err != nil {
		return fmt.Errorf("run TUI: %w", err)
	}
	if recorder != nil {
		if err := recorder.Record("session_end", map[string]any{"ended_at": time.Now()}); err != nil {
			return err
		}
	}
	return nil
}

func optionalRecorder(writer *report.Writer) tui.Recorder {
	if writer == nil {
		return nil
	}
	return writer
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func parseFlags() options {
	var options options
	flag.DurationVar(&options.interval, "interval", time.Second, "procfs polling interval")
	flag.DurationVar(&options.duration, "duration", 0, "exit automatically after this duration")
	flag.StringVar(&options.output, "output", "", "new JSONL report path (default: current directory)")
	flag.BoolVar(&options.noReport, "no-report", false, "disable JSONL session recording")
	flag.BoolVar(&options.showBuild, "version", false, "print version and exit")
	flag.Parse()
	return options
}
