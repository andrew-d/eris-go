package eris

import (
	"fmt"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
)

const (
	// ReferenceSize is the size of the reference hash.
	ReferenceSize = blake2b.Size256

	// KeySize is the size of the encryption key.
	KeySize = chacha20.KeySize

	// ConvergenceSecretSize is the length of the convergence secret.
	ConvergenceSecretSize = 32

	referenceKeyLen = ReferenceSize + KeySize
)

// Reference is a hash of an encrypted block of data. It is defined in the ERIS
// specification as:
//
//	The reference is the unkeyed Blake2b hash of the encrypted block (32 bytes)
type Reference [ReferenceSize]byte

// isZero returns true if the reference is all zeros.
func (r Reference) isZero() bool {
	for _, b := range r {
		if b != 0 {
			return false
		}
	}
	return true
}

func (r Reference) String() string {
	return fmt.Sprintf("%x", r[:])
}

func (r Reference) MarshalText() ([]byte, error) {
	return []byte(r.String()), nil
}

// Key is the encryption key required to decrypt the block of data. It is
// defined in the ERIS specification as:
//
//	key is the ChaCha20 key to decrypt the block (32 bytes)
type Key [KeySize]byte

func (k Key) String() string {
	return fmt.Sprintf("%x", k[:])
}

// ReferenceKeyPair represents a pairing of a block reference and the key
// required to decrypt the block.
type ReferenceKeyPair struct {
	Reference Reference
	Key       Key
}

// ReadCapability is all the information required to read a piece of content
// that has been split and encrypted as per the ERIS specification.
type ReadCapability struct {
	// BlockSize is the size of the blocks that the content has been split
	// into.
	BlockSize int
	// Level is the level of the root node of the tree.
	Level int
	// Root is the reference-key pair for the root node of the tree.
	Root ReferenceKeyPair
}
