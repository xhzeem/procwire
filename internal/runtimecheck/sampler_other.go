//go:build !linux

package runtimecheck

import "context"

type unsupportedSampler struct{}

func NewSampler() Sampler { return unsupportedSampler{} }

func (unsupportedSampler) Sample(context.Context) (Sample, error) {
	return Sample{}, ErrUnsupported
}
