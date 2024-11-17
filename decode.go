package eris

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
)

var (
	ErrInvalidBlockSize = errors.New("invalid block size")
	ErrInvalidBlock     = errors.New("invalid block")
	ErrInvalidPadding   = errors.New("invalid padding")
	ErrInvalidKey       = errors.New("key in read capability is invalid")
)

// FetchFunc is the function signature for a function that fetches an encrypted
// block of data from some sort of storage given a block reference. The buf parameter
// is a slice that is guaranteed to be at least the size of a block; the
// function can reuse this storage if it wants, or it can allocate and return a
// new slice.
type FetchFunc func(ctx context.Context, ref Reference, buf []byte) ([]byte, error)

// arity returns the arity of the ERIS tree for a given block size.
func arity(blockSize int) int {
	if blockSize%(referenceKeyLen) != 0 {
		// TODO: error instead of panic?
		panic(fmt.Sprintf(
			"block size (%d) must be a multiple of %d",
			blockSize,
			ReferenceSize+KeySize,
		))
	}
	return blockSize / (referenceKeyLen)
}

func dereferenceNode(
	ctx context.Context,
	fetch FetchFunc,
	buf []byte,
	ref ReferenceKeyPair,
	level, blockSize int,
) ([]byte, error) {
	// Fetch the block.
	block, err := fetch(ctx, ref.Reference, buf)
	if err != nil {
		return nil, err
	}

	// Ensure the block is the correct size.
	if len(block) != blockSize {
		return nil, ErrInvalidBlockSize
	}
	// Ensure that the block is valid for the reference; the hash of the
	// contents returned should be the reference.
	returnedRef := blake2b.Sum256(block)
	if returnedRef != ref.Reference {
		return nil, ErrInvalidBlock
	}

	// The first byte of nonce is level of the node followed by 11 bytes of zero
	var nonce [chacha20.NonceSize]byte
	nonce[0] = byte(level)

	// Decrypt the block
	cipher, _ := chacha20.NewUnauthenticatedCipher(ref.Key[:], nonce[:])
	cipher.XORKeyStream(block, block)
	return block, nil
}

func decodeInternalNode(data []byte, blockSize int) (refs []ReferenceKeyPair, err error) {
	if extraChecks && len(data) != blockSize {
		panic("invalid data length")
	}

	for i := 0; i < len(data); i += referenceKeyLen {
		// Decode a reference from the current position in the data.
		var ref Reference
		copy(ref[:], data[i:i+ReferenceSize])

		// If the reference is zero, then we have reached the end of the
		// data and the rest of the data is padding. Double-check that
		// the rest of the buffer is zero, just to be safe.
		if ref.isZero() {
			for j := i + ReferenceSize; j < len(data); j++ {
				if data[j] != 0 {
					return nil, ErrInvalidPadding
				}
			}
			break
		}

		// Decode the key from the current position in the data, and
		// then add a ref.
		var key Key
		copy(key[:], data[i+ReferenceSize:i+referenceKeyLen])
		refs = append(refs, ReferenceKeyPair{
			Reference: ref,
			Key:       key,
		})
	}
	return refs, nil
}

// DecodeRecursive decodes the content of an ERIS tree rooted at rc and returns
// the content, or an error if the content could not be decoded.
//
// The fetch function is called to fetch blocks of data from some backing
// store; see the documentation for FetchFunc for the exact semantics.
//
// The provided context is passed to the fetch function.
func DecodeRecursive(ctx context.Context, fetch FetchFunc, rc ReadCapability) ([]byte, error) {
	blockSize := rc.BlockSize
	buf := make([]byte, blockSize)

	// Verify integrity of read capability key if level is larger than 0
	if rc.Level > 0 {
		// This is the Verify-Key function from the spec, inlined

		// Dereference the node
		node, err := dereferenceNode(ctx, fetch, buf, rc.Root, rc.Level, blockSize)
		if err != nil {
			return nil, err
		}

		// Verify integrity of key
		gotHash := blake2b.Sum256(node)
		if gotHash != rc.Root.Key {
			return nil, ErrInvalidKey
		}
	}

	var decodeRecursive func(level int, refKey ReferenceKeyPair) ([]byte, error)
	decodeRecursive = func(level int, refKey ReferenceKeyPair) ([]byte, error) {
		// Dereference the node
		node, err := dereferenceNode(ctx, fetch, buf, refKey, level, blockSize)
		if err != nil {
			return nil, err
		}

		// If the level is 0, then thi sis a leaf node and we can return
		// the contents as-is.
		if level == 0 {
			return node, nil
		}

		// Otherwise, this is an internal node and we need to decode it.
		refs, err := decodeInternalNode(node, blockSize)
		if err != nil {
			return nil, err
		}

		// Recursively decode each child node
		var output []byte
		for _, ref := range refs {
			child, err := decodeRecursive(level-1, ref)
			if err != nil {
				return nil, err
			}
			output = append(output, child...)
		}
		return output, nil
	}

	// Call through to the recursive function
	padded, err := decodeRecursive(rc.Level, rc.Root)
	if err != nil {
		return nil, err
	}
	return removePadding(padded, blockSize)
}
