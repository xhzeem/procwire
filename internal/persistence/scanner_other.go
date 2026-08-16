//go:build !linux

package persistence

import "context"

type unsupportedScanner struct{}

func NewScanner() Scanner {
	return unsupportedScanner{}
}

func (unsupportedScanner) Scan(context.Context) (Result, error) {
	return Result{}, ErrUnsupported
}
