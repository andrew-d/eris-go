package eris

import (
	"crypto/subtle"
	"encoding/base32"
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

// String implements the fmt.Stringer interface.
func (r Reference) String() string {
	return fmt.Sprintf("%x", r[:])
}

// Key is the encryption key required to decrypt the block of data. It is
// defined in the ERIS specification as:
//
//	key is the ChaCha20 key to decrypt the block (32 bytes)
type Key [KeySize]byte

// String implements the fmt.Stringer interface.
func (k Key) String() string {
	return fmt.Sprintf("%x", k[:])
}

// ReferenceKeyPair represents a pairing of a block reference and the key
// required to decrypt the block.
type ReferenceKeyPair struct {
	Reference Reference
	Key       Key
}

// Equal returns true if the two ReferenceKeyPairs are equal.
func (rk ReferenceKeyPair) Equal(other ReferenceKeyPair) bool {
	// Use crypto/subtle to do a constant-time comparison of the two
	// values, just to be safe.
	return subtle.ConstantTimeCompare(rk.Reference[:], other.Reference[:]) == 1 &&
		subtle.ConstantTimeCompare(rk.Key[:], other.Key[:]) == 1
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

// Equal returns true if the two ReadCapabilities are equal.
func (rc ReadCapability) Equal(other ReadCapability) bool {
	return rc.BlockSize == other.BlockSize &&
		rc.Level == other.Level &&
		rc.Root.Equal(other.Root)
}

// AppendBinary appends the binary representation of the ReadCapability to the
// given byte slice and returns it, or any error that occurs.
//
// The binary representation of a ReadCapability is as per the ERIS
// specification, section 2.6.
func (rc ReadCapability) AppendBinary(data []byte) ([]byte, error) {
	// The specification defines the first byte as the block size, and only
	// defines the values for 1KiB and 32KiB. However, the actual byte
	// value is the log2 of the block size, so in the future we could also
	// support arbitrary block sizes here.
	switch rc.BlockSize {
	case 1024:
		data = append(data, 0x0a)
	case 32768:
		data = append(data, 0x0f)
	default:
		return nil, fmt.Errorf("unsupported block size: %d", rc.BlockSize)
	}

	// The level is a single byte; error if it's too large.
	if rc.Level > 255 {
		return nil, fmt.Errorf("level too large: %d", rc.Level)
	}
	data = append(data, byte(rc.Level))

	// Append the root reference and key.
	data = append(data, rc.Root.Reference[:]...)
	data = append(data, rc.Root.Key[:]...)
	return data, nil
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
//
// The binary representation of a ReadCapability is as per the ERIS
// specification, section 2.6.
func (rc ReadCapability) MarshalBinary() (data []byte, err error) {
	return rc.AppendBinary(nil)
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
//
// The binary representation of a ReadCapability is as per the ERIS
// specification, section 2.6.
func (rc *ReadCapability) UnmarshalBinary(data []byte) error {
	if len(data) < 66 {
		return fmt.Errorf("data too short: %d", len(data))
	}

	// The first byte is the block size. Unmarshal as a power of two, but
	// constrain it to the specification-defined values. We can remove this
	// constraint in the future.
	rc.BlockSize = 1 << data[0]
	if rc.BlockSize != 1024 && rc.BlockSize != 32768 {
		return fmt.Errorf("unsupported block size: 0x%02x", data[0])
	}

	// The second byte is the level.
	rc.Level = int(data[1])

	// The rest of the data is the root reference and key.
	copy(rc.Root.Reference[:], data[2:34])
	copy(rc.Root.Key[:], data[34:66])
	return nil
}

// From the spec:
//
//	A read capability can be encoded as an URN [RFC8141] using the
//	namespace identifier eris and the unpadded Base32 [RFC4648] encoding of
//	the read capability as namespace specific string.
var base32Enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// URN returns the URN for the ReadCapability, as defined in the ERIS
// specification, section 2.7.
func (rc ReadCapability) URN() (string, error) {
	data, err := rc.MarshalBinary()
	if err != nil {
		return "", err
	}
	return "urn:eris:" + base32Enc.EncodeToString(data), nil
}

// MustURN is like URN, but panics if an error occurs.
func (rc ReadCapability) MustURN() string {
	urn, err := rc.URN()
	if err != nil {
		panic(err)
	}
	return urn
}

// ParseReadCapabilityURN parses a URN for a ReadCapability, as defined in the
// ERIS specification, section 2.7.
func ParseReadCapabilityURN(urn string) (rc ReadCapability, err error) {
	if urn[:9] != "urn:eris:" {
		return rc, fmt.Errorf("invalid URN prefix: %q", urn[:9])
	}
	data, err := base32Enc.DecodeString(urn[9:])
	if err != nil {
		return rc, err
	}
	return rc, rc.UnmarshalBinary(data)
}
