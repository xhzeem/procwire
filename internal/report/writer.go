package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Record struct {
	Type       string    `json:"type"`
	RecordedAt time.Time `json:"recorded_at"`
	Data       any       `json:"data,omitempty"`
}

type Writer struct {
	mu      sync.Mutex
	file    *os.File
	encoder *json.Encoder
	path    string
	closed  bool
}

func Open(path string) (*Writer, error) {
	if path == "" {
		return nil, errors.New("report path cannot be empty")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open report: %w", err)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		absolute = path
	}
	return &Writer{
		file:    file,
		encoder: json.NewEncoder(file),
		path:    absolute,
	}, nil
}

func OpenDefault(directory string, now time.Time) (*Writer, error) {
	base := fmt.Sprintf("procwire-%s", now.Format("20060102-150405"))
	for suffix := 0; suffix < 1000; suffix++ {
		name := base + ".jsonl"
		if suffix > 0 {
			name = fmt.Sprintf("%s-%d.jsonl", base, suffix)
		}
		writer, err := Open(filepath.Join(directory, name))
		if err == nil {
			return writer, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	return nil, errors.New("could not allocate a unique report filename")
}

func (w *Writer) Record(kind string, data any) error {
	if w == nil {
		return errors.New("report writer is nil")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("report is closed")
	}
	if err := w.encoder.Encode(Record{Type: kind, RecordedAt: time.Now(), Data: data}); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func (w *Writer) Path() string {
	if w == nil {
		return ""
	}
	return w.path
}

func (w *Writer) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if err := w.file.Sync(); err != nil {
		_ = w.file.Close()
		return fmt.Errorf("sync report: %w", err)
	}
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("close report: %w", err)
	}
	return nil
}
