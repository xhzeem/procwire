package main

import (
	"testing"

	"github.com/xhzeem/procwire/internal/report"
)

func TestOptionalRecorderDoesNotBoxNilWriter(t *testing.T) {
	var writer *report.Writer
	if recorder := optionalRecorder(writer); recorder != nil {
		t.Fatalf("optional recorder boxed a nil writer: %#v", recorder)
	}
}
