package eris

import (
	"errors"
	"fmt"
	"io"
	"iter"

	"github.com/andrew-d/eris-go/internal/result"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
)

const extraChecks = true

// TODO: better error return
// TODO: iterator?
func Encode(content io.Reader, secret [ConvergenceSecretSize]byte, blockSize int) ([][]byte, ReadCapability, error) {
	blocks := make([][]byte, 0) // TODO: set
	level := 0
	referenceKeyPairs := []ReferenceKeyPair{}

	// Encrypt leaf nodes into blocks and reference-key pairs.
	for block := range splitContent(content, blockSize) {
		data, err := block.Value()
		if err != nil {
			return blocks, ReadCapability{}, err
		}

		block, refKey := encryptLeafNode(data, secret)

		// Add block to set of blocks to output
		blocks = append(blocks, block)

		// Add reference-key pair to list of reference-key pairs
		referenceKeyPairs = append(referenceKeyPairs, refKey)
	}

	// We should have at least one reference-key pair.
	if extraChecks && len(referenceKeyPairs) == 0 {
		panic("no reference-key pairs")
	}

	// Construct higher levels until there is a single reference-key pair
	for len(referenceKeyPairs) > 1 {
		// Increment level
		level++

		// Construct list of nodes at current level
		nodes := constructInternalNodes(referenceKeyPairs, blockSize)

		// Clear the reference-key pairs
		referenceKeyPairs = referenceKeyPairs[:0]

		// Encrypt nodes to blocks and reference-key pairs
		for _, node := range nodes {
			block, refKey := encryptInternalNode(node, level, secret)

			// add block to set of blocks to output
			blocks = append(blocks, block)

			// Add reference-key pair to list of reference-key pairs
			referenceKeyPairs = append(referenceKeyPairs, refKey)
		}
	}

	// After constructing tree there is a single reference key pair
	if extraChecks && len(referenceKeyPairs) != 1 {
		panic(fmt.Sprintf("expected exactly 1 reference-key pair, got %d", len(referenceKeyPairs)))
	}

	// Get the root reference-key pair (pointing to the root node)
	rootRefKey := referenceKeyPairs[0]
	return blocks, ReadCapability{
		BlockSize: blockSize,
		Level:     level,
		Root:      rootRefKey,
	}, nil
}

// splitContent returns an iterator that iterates over blocks of the given
// content, each of size blockSize. The byte slice yielded by the iterator must
// not be retained after the iterator yields the next value.
//
// The last block will be padded to blockSize.
func splitContent(content io.Reader, blockSize int) iter.Seq[result.Result[[]byte]] {
	buf := make([]byte, blockSize)
	return func(yield func(result.Result[[]byte]) bool) {
		var (
			n   int
			err error
		)
		for {
			// Read exactly one block into the buffer. This has
			// three different successful return values:
			//
			// n == blockSize
			//	the buffer is full, yield it
			// n < blockSize and err == io.ErrUnexpectedEOF
			//	the buffer is partially filled, pad it and
			//	yield it, and then finish because the reader is
			//	finished
			// n == 0 and err == io.EOF
			//	the reader is empty, finish
			//
			// Any other return value is an error.
			n, err = io.ReadFull(content, buf)
			if n == blockSize {
				// Full block; don't check error since we'll
				// try on the next loop iteration.
				yield(result.Of(buf))
				continue
			}

			if errors.Is(err, io.ErrUnexpectedEOF) {
				if extraChecks {
					if n == 0 {
						panic("unexpected EOF with no data")
					}
					if n > blockSize {
						panic("unexpected EOF with too much data")
					}
				}

				// Partial block; pad it and yield it.
				padded := appendPadInput(buf[:n], blockSize)
				yield(result.Of(padded))

				// We know that we're done now
				return
			}

			if errors.Is(err, io.EOF) {
				if extraChecks && n != 0 {
					panic("EOF with data")
				}

				// Yield a fully-padded block to indicate the
				// end of the content, then finish.
				//
				// TODO: check me
				yield(result.Of(appendPadInput(buf[:0], blockSize)))
				return
			}

			// Otherwise, yield the error and finish.
			yield(result.Error[[]byte](err))
			return
		}
	}
}

// appendPadInput will pad the given block to the given size, as per the ERIS
// specification, and return the padded slice. The specification states that:
//
//	The procedure Pad(input, block-size) given input of length n adds a
//	mandatory byte valued 0x80 (hexadecimal) to input followed by m <
//	block-size bytes valued 0x00 such that n + m + 1 is the smallest
//	multiple of block-size.
//
// This is the same as the padding used in libsodium, which is defined as the
// ISO/IEC 7816-4 padding algorithm.
func appendPadInput(buf []byte, blockSize int) []byte {
	n := len(buf)
	if n > blockSize {
		panic("block too large")
	}

	// If we're already at the block size, we don't need to pad.
	if n == blockSize {
		return buf
	}

	// Calculate the number of bytes remaining to pad.
	remaining := blockSize - n - 1

	// Append the mandatory 0x80 byte.
	buf = append(buf, 0x80)

	// Append the remaining 0x00 bytes.
	for i := 0; i < remaining; i++ {
		buf = append(buf, 0x00)
	}
	return buf
}

// appendPadWithZeroes appends enough zero bytes to the given byte slice to
// make it have a given length.
func appendPadWithZeroes(buf []byte, length int) []byte {
	if len(buf) > length {
		panic("buffer too large")
	} else if len(buf) == length {
		return buf
	}
	return append(buf, make([]byte, length-len(buf))...)
}

// encryptLeafNode encrypts the given leaf node with the convergence secret, and
// returns the encrypted block along with the reference-key pair for the block.
func encryptLeafNode(node []byte, convergenceSecret [ConvergenceSecretSize]byte) (block []byte, refKey ReferenceKeyPair) {
	// Use the keyed Blake2b hash to compute the encryption key
	//
	// TODO: can cache and re-use this
	hasher, err := blake2b.New256(convergenceSecret[:])
	if extraChecks && err != nil {
		panic(err)
	}
	if _, err := hasher.Write(node); err != nil {
		panic(err)
	}

	keySlice := hasher.Sum(refKey.Key[:0])
	if extraChecks && len(keySlice) != KeySize {
		panic("keyed hash has wrong length")
	}

	// The nonce is 12 bytes of 0
	var nonce [chacha20.NonceSize]byte

	// Encrypt node to block.
	//
	// Per the ERIS spec, the 32 bit initial counter is set to null.
	cipher, _ := chacha20.NewUnauthenticatedCipher(refKey.Key[:], nonce[:])

	// TODO: can we reuse the node buffer?
	block = make([]byte, len(node))
	cipher.XORKeyStream(block, node)

	// Compute the reference to the encrypted block using unkeyed Blake2b
	refKey.Reference = blake2b.Sum256(block)

	// All done!
	return block, refKey
}

// encryptInternalNode is used to encrypt internal nodes (level 1 and above).
// It takes an unencrypted node and the level of the node as input and returns
// the encrypted block as well as a reference-key pair to the block.
func encryptInternalNode(node []byte, level int, convergenceSecret [ConvergenceSecretSize]byte) (block []byte, refKey ReferenceKeyPair) {
	if level <= 0 {
		panic("level must be at least 1")
	}
	if extraChecks && level > 255 {
		panic("level too large")
	}

	// Use the unkeyed Blake2b hash to compute the encryption key
	refKey.Key = blake2b.Sum256(node)

	// The first byte of nonce is level of the node followed by 11 bytes of zero
	var nonce [chacha20.NonceSize]byte
	nonce[0] = byte(level)

	// Encrypt node to block.
	cipher, _ := chacha20.NewUnauthenticatedCipher(refKey.Key[:], nonce[:])

	// TODO: can we reuse the node buffer?
	block = make([]byte, len(node))
	cipher.XORKeyStream(block, node)

	// Compute the reference to the encrypted block using unkeyed Blake2b
	refKey.Reference = blake2b.Sum256(block)

	return block, refKey
}

// constructInternalNodes takes as input a non-empty list of reference-key
// pairs and the block size and returns a list of nodes.
func constructInternalNodes(referenceKeyPairs []ReferenceKeyPair, blockSize int) [][]byte {
	if extraChecks && len(referenceKeyPairs) == 0 {
		panic("no reference-key pairs")
	}

	// Compute arity
	arity := blockSize / 64

	// Initialize empty list of nodes to return
	var nodes [][]byte

	for len(referenceKeyPairs) > 0 {
		// Take at most arity reference-key pairs from the left of
		// reference-key-pairs
		var (
			nodeReferenceKeyPairs []ReferenceKeyPair
			rest                  []ReferenceKeyPair
		)
		if len(referenceKeyPairs) <= arity {
			nodeReferenceKeyPairs = referenceKeyPairs
			rest = nil
		} else {
			nodeReferenceKeyPairs = referenceKeyPairs[:arity]
			rest = referenceKeyPairs[arity:]
		}

		// Concatenate all reference-key pairs to a node
		node := make([]byte, 0, len(nodeReferenceKeyPairs)*referenceKeyLen)
		for _, refKey := range nodeReferenceKeyPairs {
			node = append(node, refKey.Reference[:]...)
			node = append(node, refKey.Key[:]...)
		}

		// Make sure node has size block-size by filling up with zeroes
		// if necessary.
		if len(node) < blockSize {
			node = appendPadWithZeroes(node, blockSize)
		}

		// Add node to list of nodes to return
		nodes = append(nodes, node)

		// Set reference-key-pairs to rest
		referenceKeyPairs = rest
	}

	return nodes
}
