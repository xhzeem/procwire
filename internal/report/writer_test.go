package report

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriterCreatesPrivateJSONLAndDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.jsonl")
	writer, err := Open(path)
	if err != nil {
		t.Fatalf("open writer: %v", err)
	}
	if err := writer.Record("test", map[string]string{"value": "ok"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("report mode = %o, want 600", info.Mode().Perm())
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		t.Fatal("report is empty")
	}
	var record Record
	if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
		t.Fatalf("decode record: %v", err)
	}
	if record.Type != "test" {
		t.Fatalf("record type = %q", record.Type)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("Open overwrote an existing report")
	}
}

func TestNilWriterMethodsAreSafe(t *testing.T) {
	var writer *Writer
	if err := writer.Record("test", nil); err == nil {
		t.Fatal("nil writer Record returned no error")
	}
	if path := writer.Path(); path != "" {
		t.Fatalf("nil writer path = %q", path)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("nil writer Close: %v", err)
	}
}
