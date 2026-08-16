//go:build !linux

package observe

import "context"

type unsupportedCollector struct{}

func NewCollector() Collector {
	return unsupportedCollector{}
}

func (unsupportedCollector) Snapshot(context.Context) (Snapshot, error) {
	return Snapshot{}, ErrUnsupported
}
