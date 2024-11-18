package eris

import (
	"io"
	"testing"
)

// BenchmarkSplitterSmall benchmarks how fast we are at splitting a "small" bit
// of data into chunks; it usually doesn't make sense to use 1KiB blocks for
// anything over about 16KiB of data, so we test at that point.
func BenchmarkSplitterSmall(b *testing.B) {
	benchmarkSplitter(b, 1*1024, 16*1024)
}

// BenchmarkSplitter benchmarks how fast we are at splitting data into chunks.
func BenchmarkSplitter(b *testing.B) {
	sizes := []struct {
		name string
		size int64
	}{
		{"32KiB", 32 * 1024},
		{"100KiB", 100 * 1024},
		{"1MiB", 1 * 1024 * 1024},
		{"10MiB", 10 * 1024 * 1024},
		{"100MiB", 100 * 1024 * 1024},
	}

	for _, size := range sizes {
		b.Run("Size="+size.name, func(b *testing.B) {
			benchmarkSplitter(b, 32*1024, size.size)
		})
	}
}

func benchmarkSplitter(b *testing.B, blockSize int, size int64) {
	b.Helper()

	// Manually construct a LimitedReader here so that we can reset it by
	// changing the N field without needing to allocate a new one.
	lr := &io.LimitedReader{
		R: onesReader{},
		N: size,
	}
	s := newSplitter(lr, blockSize)

	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()

	var blocks int64
	for i := 0; i < b.N; i++ {
		lr.N = size // reset without allocation
		s.Reset(lr)
		for s.Next() {
			blocks++
		}
		if s.Err() != nil {
			b.Fatalf("unexpected error: %v", s.Err())
		}
	}
}

func TestSplitter_NoAllocs(t *testing.T) {
	lr := &io.LimitedReader{
		R: onesReader{},
		N: 10 * 1024 * 1024,
	}
	s := newSplitter(lr, 32*1024)

	// This should not allocate any memory.
	allocs := testing.AllocsPerRun(1000, func() {
		s.Reset(lr)
		for s.Next() {
		}
		if s.Err() != nil {
			t.Fatalf("unexpected error: %v", s.Err())
		}
	})
	if allocs > 0 {
		t.Fatalf("unexpected allocations: %f", allocs)
	}
}

type onesReader struct{}

func (onesReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 1
	}
	return len(b), nil
}
