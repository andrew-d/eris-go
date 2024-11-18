package eris

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"
)

type testVector struct {
	// Inputs to the test

	ID                int    `json:"id"`
	Type              string `json:"type"`
	SpecVersion       string `json:"spec-version"`
	Name              string `json:"name"`
	Description       string `json:"description"`
	Content           string `json:"content"`
	ConvergenceSecret string `json:"convergence-secret"`
	BlockSize         int    `json:"block-size"`

	// Expected outputs

	ReadCapability testReadCapability `json:"read-capability"`
	URN            string             `json:"urn"`
	Blocks         map[string]string  `json:"blocks"`
}

type testReadCapability struct {
	BlockSize     int    `json:"block-size"`
	Level         int    `json:"level"`
	RootReference string `json:"root-reference"`
	RootKey       string `json:"root-key"`
}

func (trc testReadCapability) ReadCapability(t *testing.T) ReadCapability {
	rc := ReadCapability{
		BlockSize: trc.BlockSize,
		Level:     trc.Level,
	}
	copy(rc.Root.Reference[:], mustDecodeBase32(t, trc.RootReference))
	copy(rc.Root.Key[:], mustDecodeBase32(t, trc.RootKey))
	return rc
}

// readTestVectors reads all test vectors from disk and returns them as an
// iterator over (name, vector) pairs.
func readTestVectors(t *testing.T) iter.Seq2[string, *testVector] {
	// Read all test vectors from disk.
	vectors, err := os.ReadDir("testdata/test-vectors")
	if err != nil {
		t.Fatal(err)
	}

	return func(yield func(string, *testVector) bool) {
		for _, tv := range vectors {
			// Ignore non-JSON files
			if tv.IsDir() || filepath.Ext(tv.Name()) != ".json" {
				continue
			}

			// Read the test vector from disk.
			f, err := os.ReadFile("testdata/test-vectors/" + tv.Name())
			if err != nil {
				t.Errorf("reading test vector %q: %v", tv.Name(), err)
				continue
			}

			// Unmarshal the test vector.
			vector := &testVector{}
			if err := json.Unmarshal(f, vector); err != nil {
				t.Errorf("unmarshaling test vector %q: %v", tv.Name(), err)
				continue
			}

			if vector.Type != "positive" && vector.Type != "negative" {
				t.Errorf("unexpected test vector type in %q: %q", tv.Name(), vector.Type)
				continue
			}

			// Sanitize the name to make targeting specific tests easier,
			// by removing brackets and replacing commas with underscores.
			name := vector.Name
			name = strings.ReplaceAll(name, "(", "")
			name = strings.ReplaceAll(name, ")", "")
			name = strings.ReplaceAll(name, ",", "_")
			name = strings.ReplaceAll(name, "-", "_")
			name = strings.TrimRight(name, "_")

			if !yield(name, vector) {
				return
			}
		}
	}
}

func TestPositive(t *testing.T) {
	for name, vector := range readTestVectors(t) {
		if vector.Type != "positive" {
			continue
		}

		t.Run(name, func(t *testing.T) {
			t.Logf("Running test vector %q", vector.Name)
			t.Logf("Description: %s", vector.Description)
			t.Run("Encode", func(t *testing.T) {
				testEncode(t, vector)
			})
			testDecode(t, vector)
		})
	}
}

func TestNegative(t *testing.T) {
	for name, vector := range readTestVectors(t) {
		if vector.Type != "negative" {
			continue
		}

		t.Run(name, func(t *testing.T) {
			t.Logf("Running test vector %q", vector.Name)
			t.Logf("Description: %s", vector.Description)
			testDecode(t, vector)
		})
	}
}

func testEncode(t *testing.T, vector *testVector) {
	content := mustDecodeBase32(t, vector.Content)
	secret := mustDecodeBase32(t, vector.ConvergenceSecret)
	if len(secret) != ConvergenceSecretSize {
		t.Fatalf("convergence secret has unexpected length: %d", len(secret))
	}

	var csecret [ConvergenceSecretSize]byte
	copy(csecret[:], secret)

	// Encode the test vector.
	var blocks [][]byte
	enc := NewEncoder(bytes.NewReader(content), csecret, vector.BlockSize)
	for enc.Next() {
		blocks = append(blocks, enc.Block())
	}
	if err := enc.Err(); err != nil {
		t.Fatalf("error encoding: %v", err)
	}
	rc := enc.Capability()

	// Check that the read capability matches the expected value.
	if rc.BlockSize != vector.ReadCapability.BlockSize {
		t.Errorf("ReadCapability block size mismatch: got %d, want %d", rc.BlockSize, vector.ReadCapability.BlockSize)
	}
	if rc.Level != vector.ReadCapability.Level {
		t.Errorf("ReadCapability level mismatch: got %d, want %d", rc.Level, vector.ReadCapability.Level)
	}

	// Decode and check root reference and root key.
	wantRootReference := mustDecodeBase32(t, vector.ReadCapability.RootReference)
	wantRootKey := mustDecodeBase32(t, vector.ReadCapability.RootKey)
	if !bytes.Equal(rc.Root.Reference[:], wantRootReference) {
		t.Errorf("ReadCapability root reference mismatch: got %x, want %x", rc.Root.Reference, wantRootReference)
	}
	if !bytes.Equal(rc.Root.Key[:], wantRootKey) {
		t.Errorf("ReadCapability root key mismatch: got %x, want %x", rc.Root.Key, wantRootKey)
	}

	// Ensure that the URN marshals to the expected value.
	urn, err := rc.URN()
	if err != nil {
		t.Errorf("error marshaling URN: %v", err)
	}
	if urn != vector.URN {
		t.Errorf("URN mismatch: got %q, want %q", urn, vector.URN)
	}

	// Unmarshal the vector's URN and verify that it also unmarshals and
	// equals the ReadCapability that we just got.
	rc2, err := ParseReadCapabilityURN(vector.URN)
	if err != nil {
		t.Errorf("error unmarshaling URN: %v", err)
	}
	if !rc2.Equal(rc) {
		t.Errorf("ReadCapability mismatch after unmarshaling URN")
	}

	// Verify that we have exactly the same number of blocks as the
	// test vector.
	if len(blocks) != len(vector.Blocks) {
		t.Errorf("number of blocks mismatch: got %d, want %d", len(blocks), len(vector.Blocks))
	}

	// Compare each block with the expected value. The map is keyed
	// by the reference for that block, so we can check by
	// iterating over every returned block and checking if the
	// reference is in the expected blocks.
	for _, block := range blocks {
		blockRef := blake2b.Sum256(block)
		blockRef32 := base32Enc.EncodeToString(blockRef[:])

		wantBlock, ok := vector.Blocks[blockRef32]
		if !ok {
			t.Errorf("block reference %q not found in test vector", blockRef32)
			continue
		}

		wantContents := mustDecodeBase32(t, wantBlock)
		if !bytes.Equal(block, wantContents) {
			t.Errorf("block contents mismatch for reference %q", blockRef32)
		}
	}
}

func testDecode(t *testing.T, vector *testVector) {
	// Our fetch function just looks up and returns the block from
	// the test vector, or an error if it's not found.
	fetch := func(_ context.Context, ref Reference, buf []byte) ([]byte, error) {
		ref32 := base32Enc.EncodeToString(ref[:])
		block, ok := vector.Blocks[ref32]
		if !ok {
			return nil, fmt.Errorf("block %q not found", ref32)
		}
		return mustDecodeBase32(t, block), nil
	}

	t.Run("Decode", func(t *testing.T) {
		// Construct a ReadCapability from the test vector.
		rc := vector.ReadCapability.ReadCapability(t)

		// Decode the test vector.
		decoded, err := DecodeRecursive(context.Background(), fetch, rc)

		// Depending on whether this is a positive or negative test vector, we either want an error or not.
		if vector.Type == "positive" {
			if err != nil {
				t.Fatalf("error decoding: %v", err)
			}

			wantContent := mustDecodeBase32(t, vector.Content)
			if !bytes.Equal(decoded, wantContent) {
				t.Errorf("decoded content mismatch")
			}
		} else {
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			t.Logf("got expected error: %v", err)
		}
	})

	t.Run("DecodeIter", func(t *testing.T) {
		// Construct a ReadCapability from the test vector.
		rc := vector.ReadCapability.ReadCapability(t)

		// Decode the test vector.
		dec := NewDecoder(fetch, rc)
		ctx := context.Background()

		var decoded []byte
		for dec.Next(ctx) {
			curr := dec.Block()
			if len(curr) == 0 {
				t.Errorf("empty block")
			}
			decoded = append(decoded, curr...)
		}

		err := dec.Err()

		// Depending on whether this is a positive or negative test
		// vector, we either want an error or not.
		if vector.Type == "positive" {
			if err != nil {
				t.Fatalf("error decoding: %v", err)
			}

			wantContent := mustDecodeBase32(t, vector.Content)
			if !bytes.Equal(decoded, wantContent) {
				t.Errorf("decoded content mismatch")
			}
		} else {
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			t.Logf("got expected error: %v", err)
		}
	})
}

func mustDecodeBase32(t *testing.T, input string) []byte {
	t.Helper()
	decoded, err := base32Enc.DecodeString(input)
	if err != nil {
		t.Fatalf("decoding base32: %v", err)
	}
	return decoded
}
