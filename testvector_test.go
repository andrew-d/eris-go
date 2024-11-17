package eris

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
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

func TestTestVectors(t *testing.T) {
	// Read all test vectors from disk.
	vectors, err := os.ReadDir("testdata/test-vectors")
	if err != nil {
		t.Fatal(err)
	}

	// For each test vector, run a sub-test.
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
		var vector testVector
		if err := json.Unmarshal(f, &vector); err != nil {
			t.Errorf("unmarshaling test vector %q: %v", tv.Name(), err)
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

		t.Run(name, func(t *testing.T) {
			runTestVector(t, &vector)
		})
	}
}

func runTestVector(t *testing.T, vector *testVector) {
	t.Logf("Running test vector %q", vector.Name)
	t.Logf("Description: %s", vector.Description)

	t.Run("Encode", func(t *testing.T) {
		// Only test encoding for 'positive' test vectors, which are expected to succeed.
		if vector.Type != "positive" {
			t.Skip("skipping Encode test for negative test vector")
		}

		content := mustDecodeBase32(t, vector.Content)
		secret := mustDecodeBase32(t, vector.ConvergenceSecret)
		if len(secret) != ConvergenceSecretSize {
			t.Fatalf("convergence secret has unexpected length: %d", len(secret))
		}

		var csecret [ConvergenceSecretSize]byte
		copy(csecret[:], secret)

		// Encode the test vector.
		blocks, rc, err := Encode(
			bytes.NewReader(content),
			csecret,
			vector.BlockSize,
		)
		if err != nil {
			t.Errorf("encoding: %v", err)
			return
		}

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
	})
}

var base32Enc = base32.StdEncoding.WithPadding(base32.NoPadding)

func mustDecodeBase32(t *testing.T, input string) []byte {
	t.Helper()
	decoded, err := base32Enc.DecodeString(input)
	if err != nil {
		t.Fatalf("decoding base32: %v", err)
	}
	return decoded
}
