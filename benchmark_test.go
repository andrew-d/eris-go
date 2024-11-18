package eris

import (
	"io"
	"testing"
)

// BenchmarkEncodeSmall benchmarks how fast we are at encoding a "small" bit of
// data; it usually doesn't make sense to use 1KiB blocks for anything over
// about 16KiB of data, so we test at that point.
func BenchmarkEncodeSmall(b *testing.B) {
	benchmarkEncode(b, 16*1024, 1*1024)
}

func BenchmarkEncode(b *testing.B) {
	sizes := []struct {
		name string
		size int64
	}{
		{"32KiB", 32 * 1024},
		{"100KiB", 100 * 1024},
		{"1MiB", 1 * 1024 * 1024},
		{"10MiB", 10 * 1024 * 1024},
	}
	for _, size := range sizes {
		b.Run("Size="+size.name, func(b *testing.B) {
			benchmarkEncode(b, size.size, 32*1024)
		})
	}
}

func benchmarkEncode(b *testing.B, size int64, blockSize int) {
	// Create an io.Reader that reads zero bytes, to use as
	// our content.
	lr := &io.LimitedReader{R: onesReader{}, N: size}
	b.SetBytes(size)

	// The secret doesn't matter for this benchmark, so we
	// just use a zero value.
	var secret [ConvergenceSecretSize]byte

	// Reset the benchmark timer.
	b.ReportAllocs()
	b.ResetTimer()

	// Repeatedly encode the content; we do this N times so
	// that the benchmark is statistically significant.
	enc := NewEncoder(lr, secret, blockSize)
	for i := 0; i < b.N; i++ {
		lr.N = size // reset without alloc
		enc.reset(lr)
		for enc.Next() {
			io.Discard.Write(enc.Block())
		}
		if err := enc.Err(); err != nil {
			b.Fatalf("error encoding: %v", err)
		}
	}
}
