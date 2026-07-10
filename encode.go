package eris

import (
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
)

// Encoder is used to encode some content into the ERIS format: a set of
// encrypted blocks, and a "read capability" that contains all the information
// needed to read and decrypt the content.
type Encoder struct {
	// state is the current state of the encoder. It is one of the
	// following values:
	//	0 - the encoder is reading input content
	//	1 - the encoder is generating internal nodes
	//	2 - the encoder has finished generating blocks
	state int

	// err is the error that caused the encoder to stop. If err is not nil,
	// the Next method will always return false.
	err error

	// content is the content that is being encoded.
	content io.Reader

	// secret is the convergence secret that is used to encrypt the content.
	secret [ConvergenceSecretSize]byte

	// blockSize is the size of each block in the ERIS tree.
	blockSize int

	// blocks tracks whether we have already seen a block, so that we can
	// avoid emitting duplicates.
	blocks map[Reference]bool

	// currBlock is the current block of data that was encoded.
	currBlock []byte

	// currRef is the current reference of the block of data that was encoded.
	currRef Reference

	// level is the current level of the ERIS tree.
	level int

	// referenceKeyPairs is the list of reference-key pairs that have been
	// generated so far, and is mutated as the encoder progresses.
	referenceKeyPairs []ReferenceKeyPair

	// rootRefKey is the reference-key pair for the root node of the ERIS
	// tree. It is only valid when the encoder is in state 2.
	rootRefKey ReferenceKeyPair

	// blakeHasher is a hash.Hash that is initialized with
	// blake2b.New256(convergenceSecret). It can be Reset and used to hash
	// without allocating a new hasher on every block.
	blakeHasher hash.Hash

	// The following fields are used to store information in state 0

	// splitter is used to chunk the input content into blocks.
	splitter *splitter

	// The following fields are used to store information in state 1

	// internalNodes is the list of internal nodes that have been generated
	// for the current level in the tree.
	//
	// TODO: this is eagerly generated, and for a sufficiently-large tree,
	// can use a lot of memory; we should consider generating it lazily.
	internalNodes [][]byte

	// internalNodePos is the current position in internalNodes that we're constructing.
	internalNodePos int
}

func NewEncoder(content io.Reader, secret [ConvergenceSecretSize]byte, blockSize int) *Encoder {
	blakeHasher, err := blake2b.New256(secret[:])
	if extraChecks && err != nil {
		panic(err)
	}

	return &Encoder{
		state:       0, // initial state
		content:     content,
		secret:      secret,
		blockSize:   blockSize,
		blocks:      make(map[Reference]bool),
		level:       0, // level starts at 0
		blakeHasher: blakeHasher,
	}
}

// reset will reset the encoder to its initial state, using the given reader
// as the new content to encode. The secret and block size are not changed.
//
// This is currently not public because it's not clear if it's useful to
// to consumers; we use it internally to reset the encoder when we're
// doing benchmarks.
func (e *Encoder) reset(r io.Reader) {
	e.state = 0
	e.err = nil
	e.content = r
	e.level = 0

	// Clear, but don't reset, the blocks map
	for k := range e.blocks {
		delete(e.blocks, k)
	}

	// Clear some other internal state that we may or may not have set.
	e.currBlock = nil
	e.currRef = Reference{}
	e.referenceKeyPairs = e.referenceKeyPairs[:0]
	e.rootRefKey = ReferenceKeyPair{}
	e.internalNodes = e.internalNodes[:0]
	e.internalNodePos = 0

	// Reset our splitter; we could also nil this out, but this avoids an
	// allocation.
	if e.splitter != nil {
		e.splitter.Reset(r)
	}

	// Don't need to reset our Blake2b hasher, since encryptLeafNode always
	// calls Reset before using it, but let's do that anyway for safety.
	e.blakeHasher.Reset()
}

// Block returns the current block of data that was encoded.
//
// It is only valid to call this method after a call to the Next method has
// returned true.
func (e *Encoder) Block() []byte {
	if e.err != nil {
		if extraChecks {
			panic("cannot call Block() after error")
		}
		return nil
	}
	return e.currBlock
}

// Reference returns the Reference of the current block of data that was
// encoded.
//
// It is only valid to call this method after a call to the Next method has
// returned true.
func (e *Encoder) Reference() Reference {
	if e.err != nil {
		if extraChecks {
			panic("cannot call Reference() after error")
		}
		return Reference{}
	}
	return e.currRef
}

// Err returns the error that caused the encoder to stop, if any.
func (e *Encoder) Err() error {
	return e.err
}

// Capability returns the read capability that can be used to read the encoded
// data.
//
// It is only valid to call this method after a call to the Next method has
// returned false, and if there was no error.
func (e *Encoder) Capability() ReadCapability {
	if e.err != nil {
		return ReadCapability{}
	}
	return ReadCapability{
		BlockSize: e.blockSize,
		Level:     e.level,
		Root:      e.rootRefKey,
	}
}

// stateRes is a helper type for our internal state machine.
type stateRes int

const (
	stateReturnTrue stateRes = iota
	stateReturnFalse
	stateContinue
)

// Next will advance the state of the Encoder and return true if there is more work to be done.
//
// When Next returns true, the caller should call the Block() method to get the
// next block of data that was encoded.
//
// When Next returns false, the caller should first check the Err() method to
// see if there was an error. If no error occurred, the caller should then call
// the Capability() method to get the read capability that can be used to read
// the encoded data.
func (e *Encoder) Next() bool {
	if e.err != nil {
		return false
	}

	for {
		var res stateRes
		switch e.state {
		case 0:
			res = e.nextContent()
		case 1:
			res = e.nextInternalNodes()
		case 2:
			res = stateReturnFalse
		default:
			panic("invalid state")
		}

		switch res {
		case stateReturnTrue:
			return true
		case stateReturnFalse:
			return false
		case stateContinue:
			// fall through and continue; usually when
			// transitioning to the next state
		}
	}
}

// maybeEmitBlock will "emit" a block of data if it hasn't been seen before.
//
// If the block has already been seen, this method will return false. If the
// block hasn't been seen, it will be added to the set of seen blocks and
// stored in e.currBlock, and the method will return true.
func (e *Encoder) maybeEmitBlock(block []byte, ref Reference) bool {
	if _, ok := e.blocks[ref]; ok {
		return false
	}

	e.blocks[ref] = true
	e.currBlock = block
	e.currRef = ref
	return true
}

func (e *Encoder) nextContent() stateRes {
	if e.splitter == nil {
		e.splitter = newSplitter(e.content, e.blockSize)
	}

	// Repeatedly read blocks of data from our input until we get a block
	// that we haven't seen yet.
	for e.splitter.Next() {
		data := e.splitter.Block()

		// Encrypt the block; this overwrites the 'data' buffer and
		// returns it, which means that we can't retain the buffer
		// after the next call to splitter.Next().
		//
		// That's fine in this case, since we use the block in
		// maybeEmitBlock and return if it's a new block, so the caller
		// can use the buffer until the next call to Next().
		block, refKey := encryptLeafNode(data, e.blakeHasher)

		// Add the reference-key pair to the list of reference-key pairs. We
		// need to do this even if we've already seen this block, since the
		// reference-key pair is used to construct the internal nodes in the
		// tree.
		e.referenceKeyPairs = append(e.referenceKeyPairs, refKey)

		// If we have already seen this block, skip it.
		if !e.maybeEmitBlock(block, refKey.Reference) {
			continue
		}

		// Return true to tell the caller that there's a new Block to read.
		return stateReturnTrue
	}

	// If we get here, we need to see if the splitter encountered an error.
	if err := e.splitter.Err(); err != nil {
		e.err = err
		return stateReturnFalse
	}

	// Otherwise, we're done reading the content. Transition to the next
	// state.
	e.state = 1
	return stateContinue
}

// nextInternalNodes will construct higher levels until there is a single
// reference-key pair.
func (e *Encoder) nextInternalNodes() stateRes {
	// If we don't have any internal nodes, populate it from the global set
	// of reference-key pairs. This happens when entering this state from
	// the "reading content" state, or when incrementing the tree level.
	if e.internalNodePos == len(e.internalNodes) {
		// We should have at least one reference-key pair.
		if extraChecks && len(e.referenceKeyPairs) < 1 {
			panic("no reference-key pairs")
		}

		// If we have exactly one reference-key pair, we're done; move
		// to the terminal state.
		if len(e.referenceKeyPairs) == 1 {
			e.rootRefKey = e.referenceKeyPairs[0]
			e.state = 2
			return stateContinue
		}

		// Otherwise, we have more than one reference-key pair, so we
		// need to build a tree of internal nodes.

		// Increment level when we're about to start constructing a
		// layer in the tree.
		e.level++

		// Construct list of nodes at current level
		e.internalNodes = constructInternalNodes(e.referenceKeyPairs, e.blockSize)

		// Clear the reference-key pairs
		e.referenceKeyPairs = e.referenceKeyPairs[:0]

		// Reset our internal node position
		e.internalNodePos = 0
	}

	if extraChecks && e.internalNodePos >= len(e.internalNodes) {
		panic(fmt.Sprintf("internal node position out of bounds: %d >= %d", e.internalNodePos, len(e.internalNodes)))
	}

	// Encrypt nodes to blocks and reference-key pairs. Repeat until we get
	// a block that we haven't seen before.
	for i := e.internalNodePos; i < len(e.internalNodes); i++ {
		block, refKey := encryptInternalNode(e.internalNodes[i], e.level)

		// Add reference-key pair to list of reference-key pairs
		e.referenceKeyPairs = append(e.referenceKeyPairs, refKey)

		// If we have already seen this block, don't emit it and
		// continue to generate the next block.
		if !e.maybeEmitBlock(block, refKey.Reference) {
			continue
		}

		// Otherwise, we have a new block to emit.
		e.internalNodePos = i + 1
		return stateReturnTrue
	}

	// If we get here, we've finished generating all the blocks for the
	// current level. Tell the caller to continue the state loop, which
	// will call ourselves again to either move to the next level or
	// finish.
	return stateContinue
}

// appendPadWithZeroes appends enough zero bytes to the given byte slice to
// make it have a given length.
func appendPadWithZeroes(buf []byte, length int) []byte {
	if len(buf) > length {
		panic("buffer too large")
	} else if len(buf) == length {
		return buf
	}

	// If the buffer's given capacity is already large enough, we can
	// just slice it to the desired length, and then zero out the
	// remaining bytes.
	if cap(buf) >= length {
		initialLen := len(buf)
		buf = buf[:length]
		for i := initialLen; i < length; i++ {
			buf[i] = 0
		}
		return buf
	}

	// Otherwise, we need to allocate a new buffer and copy the old
	// buffer into it.
	return append(buf, make([]byte, length-len(buf))...)
}

// encryptLeafNode encrypts the given leaf node, and returns the encrypted
// block along with the reference-key pair for the block.
//
// The given hasher is used to construct the key for this block; it should be
// constructed using blake2b.New256(convergenceSecret), and will be reset
// before use.
func encryptLeafNode(node []byte, hasher hash.Hash) (block []byte, refKey ReferenceKeyPair) {
	// Use the keyed Blake2b hash to compute the encryption key
	hasher.Reset()
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
	cipher.XORKeyStream(node, node)

	// Compute the reference to the encrypted block using unkeyed Blake2b
	refKey.Reference = blake2b.Sum256(node)

	// All done!
	return node, refKey
}

// encryptInternalNode is used to encrypt internal nodes (level 1 and above).
// It takes an unencrypted node and the level of the node as input and returns
// the encrypted block as well as a reference-key pair to the block.
func encryptInternalNode(node []byte, level int) (block []byte, refKey ReferenceKeyPair) {
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

	// Reuse the 'node' buffer and encrypt in-place.
	cipher.XORKeyStream(node, node)

	// Compute the reference to the encrypted block using unkeyed Blake2b
	refKey.Reference = blake2b.Sum256(node)

	return node, refKey
}

// constructInternalNodes takes as input a non-empty list of reference-key
// pairs and the block size and returns a list of nodes.
func constructInternalNodes(referenceKeyPairs []ReferenceKeyPair, blockSize int) [][]byte {
	if extraChecks && len(referenceKeyPairs) == 0 {
		panic("no reference-key pairs")
	}

	// Compute arity
	arity := arity(blockSize)

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
