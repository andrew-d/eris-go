package eris

import (
	"io"
	"maps"
	"reflect"
	"testing"
)

// TestReset verifies that the reset method on the Encoder will actually reset
// all fields, by using the reflect package to check the values of the fields
// after encoding some data.
func TestEncoder_Reset(t *testing.T) {
	lr := &io.LimitedReader{R: onesReader{}, N: 10 * 1024 * 1024}
	secret := [ConvergenceSecretSize]byte{}

	// Create an encoder and encode some data.
	enc := NewEncoder(lr, secret, 32*1024)
	for enc.Next() {
		io.Discard.Write(enc.Block())
	}
	if err := enc.Err(); err != nil {
		t.Fatalf("error encoding: %v", err)
	}

	// Reset the encoder and check that all fields are reset.
	enc.reset(lr)

	// Ignore certain fields that we know must be non-zero.
	assertStructEmpty(t, enc, map[string]bool{
		// These are parameters and cannot be empty.
		"content":   true,
		"blockSize": true,

		// Checked below
		"splitter": true,
	})

	// Check that the splitter is also empty.
	assertStructEmpty(t, enc.splitter, map[string]bool{
		// These are parameters and cannot be empty.
		"r":         true,
		"blockSize": true,

		// Checked below
		"buf": true,
	})

	// Check that the buffer is exactly blockSize.
	if len(enc.splitter.buf) != enc.splitter.blockSize {
		t.Errorf("error: splitter.buf has length %d, want %d",
			len(enc.splitter.buf), enc.splitter.blockSize)
	}
}

func assertStructEmpty(t *testing.T, ss any, wantNonZero map[string]bool) {
	// Copy so that we can delete from it.
	wantNonZero = maps.Clone(wantNonZero)

	// Iterate over all fields using the reflect package.
	ty := reflect.TypeOf(ss).Elem()
	val := reflect.ValueOf(ss).Elem()
	for i := 0; i < ty.NumField(); i++ {
		field := val.Field(i)
		fieldType := ty.Field(i)

		if _, ok := wantNonZero[fieldType.Name]; ok {
			t.Logf("%s: skipping field %s that is expected to be non-zero", ty.Name(), fieldType.Name)

			// Delete from the map so we can see if we have any
			// unexpected "want" fields later.
			delete(wantNonZero, fieldType.Name)
			continue
		}

		if field.IsZero() {
			t.Logf("%s: field %s: is zero", ty.Name(), fieldType.Name)
			continue
		}

		// If this is a map or a slice, check if the length is zero.
		if field.Kind() == reflect.Map || field.Kind() == reflect.Slice {
			flen := field.Len()
			if flen == 0 {
				t.Logf("%s: field %s: is empty", ty.Name(), fieldType.Name)
				continue
			}

			t.Errorf("error: %s: field %s: has length %d, want 0", ty.Name(), fieldType.Name, flen)
			continue
		}

		t.Errorf("error: %s: field %s: is non-zero", ty.Name(), fieldType.Name)
	}

	if len(wantNonZero) > 0 {
		t.Errorf("%s: fields in wantNonZero not found in type: %v", ty.Name(), maps.Keys(wantNonZero))
	}
}
