package eris

import (
	"context"

	"golang.org/x/crypto/blake2b"
)

// decodeNode is a wrapper type that represents a node in an ERIS-encoded tree
// along with the level of the node.
type decodeNode struct {
	ref   ReferenceKeyPair
	level int
}

// Decoder is a streaming decode that can be used to decode an ERIS-encoded
// stream of content into the original data. It is agnostic to how encrypted
// blocks of data are fetched or how output is written.
type Decoder struct {
	// fetch is the function that will be used to fetch encrypted blocks of data
	fetch FetchFunc

	// rc is the read capability that describes the ERIS-encoded content
	// to be fetched and decoded
	rc ReadCapability

	// state is the current state of the decoder. It is one of the
	// following values:
	//	0 - the decoder is at the root node
	//	1 - the decoder is at an intermediate node
	state int

	// err is the error that occurred during decoding, if any.
	err error

	// buf is a buffer of byteSize that can be used as intermediate storage
	// when fetching blocks
	buf []byte

	// block is the current block of the original content that has been
	// decoded. Depending on the fetch function, this may be the same as
	// the buf field.
	block []byte

	// stack is the current stack of nodes that we're processing.
	stack []decodeNode

	// didInit is whether we initialized the decoder; we do this on the
	// first call to Next so that constructing a decoder doesn't require a
	// call to fetch.
	didInit bool
}

// NewDecoder creates a new Decoder instance.
func NewDecoder(fetch FetchFunc, rc ReadCapability) *Decoder {
	return &Decoder{
		fetch: fetch,
		rc:    rc,
		buf:   make([]byte, rc.BlockSize),
	}
}

// Next will fetch blocks of the ERIS-encoded tree and decode them until it
// retrieves a block of the original content or until an error occurs.
//
// If an error occurs or decoding is finished, the function will return false.
// The caller should call the Err method to check if an error occurred.
//
// If no error occurs and decoding is not finished, the function will return
// true and the Block function can be called to retrieve the next block of the
// original content.
//
// The provided Context will be passed to the fetch function.
func (d *Decoder) Next(ctx context.Context) bool {
	if d.err != nil {
		return false
	}

	if !d.didInit {
		// Verify integrity of read capability key if level is larger
		// than 0, and as a side effect, fill in the stack with the
		// children of the root node.
		//
		// This is the Verify-Key function from the spec, inlined.
		if d.rc.Level > 0 {
			node, err := d.dereferenceNode(ctx, d.rc.Root, d.rc.Level)
			if err != nil {
				d.err = err
				return false
			}

			// Verify integrity of key
			gotHash := blake2b.Sum256(node)
			if gotHash != d.rc.Root.Key {
				d.err = ErrInvalidKey
				return false
			}

			// Fill in the stack with the children of the root node.
			if err := d.decodeInternalNode(node, d.rc.Level-1); err != nil {
				d.err = err
				return false
			}
		} else {
			// Otherwise, the root node is also the (only) leaf
			// node, and we can just set it directly in the stack.
			d.stack = append(d.stack, decodeNode{
				ref:   d.rc.Root,
				level: 0,
			})
		}

		d.didInit = true
	}

	// Continue searching until we find a leaf node or exhaust the stack.
	for len(d.stack) > 0 {
		// Pop the current node from the stack.
		lastIdx := len(d.stack) - 1
		curr := d.stack[lastIdx]
		d.stack = d.stack[:lastIdx]
		isFinal := len(d.stack) == 0

		if extraChecks && curr.level < 0 {
			panic("invalid level")
		}

		// Fetch the node and decrypt it.
		buf, err := d.dereferenceNode(ctx, curr.ref, curr.level)
		if err != nil {
			d.err = err
			return false
		}

		// If this node is a leaf node (with level 0), then we have
		// some content that we can output.
		if curr.level == 0 {
			d.block = buf

			// If this is the last block, then we need to unpad it.
			if isFinal {
				var err error
				d.block, err = removePadding(d.block, d.rc.BlockSize)
				if err != nil {
					d.err = err
					return false
				}

				// If we unpadded the block to zero length, then we're
				// done and have nothing left to do.
				//
				// Technically we could return true here and
				// let the caller observe a zero-length
				// Block(), but it's easier to just return
				// false given that we know we're done.
				if len(d.block) == 0 {
					return false
				}
			}
			return true
		}

		// Otherwise, this is an intermediate node, so we need to
		// process all children of this node.
		if err := d.decodeInternalNode(buf, curr.level-1); err != nil {
			d.err = err
			return false
		}

		// If we decoded no internal nodes, and this was the last node
		// in the stack, then something went wrong.
		if extraChecks && len(d.stack) == 0 {
			panic("no internal nodes decoded")
		}

		// Continue through to the next iteration of the loop to either
		// traverse further down the tree or start emitting output
		// blocks to the caller.
	}

	// If we reach this point, then we've exhausted the stack and there
	// are no more nodes to process.
	return false
}

// decodeInternalNode will decode an internal node and push all children onto
// the stack.
func (d *Decoder) decodeInternalNode(node []byte, atLevel int) error {
	if extraChecks && atLevel < 0 {
		panic("invalid level")
	}

	refs, err := decodeInternalNode(node, d.rc.BlockSize)
	if err != nil {
		return err
	}

	// Push all children onto the stack in reverse order. This ensures
	// we process them in left-to-right order when popping.
	for i := len(refs) - 1; i >= 0; i-- {
		d.stack = append(d.stack, decodeNode{
			ref:   refs[i],
			level: atLevel,
		})
	}
	return nil
}

func (d *Decoder) dereferenceNode(ctx context.Context, ref ReferenceKeyPair, level int) ([]byte, error) {
	return dereferenceNode(
		ctx,
		d.fetch,
		d.buf,
		ref,
		level,
		d.rc.BlockSize,
	)
}

// Block returns the next block of the original content.
func (d *Decoder) Block() []byte {
	if d.err != nil {
		if extraChecks {
			panic("cannot call Block() after error")
		}
		return nil
	}
	return d.block
}

// Err returns the error that occurred during decoding, if any.
func (d *Decoder) Err() error {
	return d.err
}
