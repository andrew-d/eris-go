package eris

import (
	"errors"
	"io"
)

// splitter is an iterator that will read blocks of bytes from an underlying
// reader of a given block size. The final block will be padded to blockSize.
type splitter struct {
	r         io.Reader
	blockSize int

	// err stores the last error encountered by the splitter.
	err error

	// buf is the working buffer for reading
	buf []byte

	// done is whether the iterator has finished. This is set when the
	// iterator needs to yield a final (padded) block, and then not
	// continue to read from the underlying reader.
	done bool
}

func newSplitter(r io.Reader, blockSize int) *splitter {
	return &splitter{
		r:         r,
		blockSize: blockSize,
		buf:       make([]byte, blockSize),
	}
}

func (s *splitter) Next() bool {
	if s.err != nil || s.done {
		return false
	}

	// Read exactly one block into the buffer. This has three different
	// successful return values:
	//
	// n == blockSize
	//	the buffer is full, yield it
	// n < blockSize and err == io.ErrUnexpectedEOF
	//	the buffer is partially filled, pad it and yield it, and then
	//	finish because the reader is finished
	// n == 0 and err == io.EOF
	//	the reader is empty, finish
	//
	// Any other return value is an error.
	n, err := io.ReadFull(s.r, s.buf)
	if n == s.blockSize {
		return true
	}

	if errors.Is(err, io.ErrUnexpectedEOF) {
		if extraChecks {
			if n == 0 {
				panic("unexpected EOF with no data")
			}
			if n > s.blockSize {
				panic("unexpected EOF with too much data")
			}
		}

		// Partial block; pad it and yield it.
		s.buf = appendPadInput(s.buf[:n], s.blockSize)
		if extraChecks && len(s.buf) != s.blockSize {
			panic("unexpected padding length")
		}

		// Ensure that we don't try to read on the next iteration.
		s.done = true
		return true
	}

	if errors.Is(err, io.EOF) {
		if extraChecks && n != 0 {
			panic("EOF with data")
		}

		// Yield a fully-padded block to indicate the
		// end of the content, then finish.
		s.buf = appendPadInput(s.buf[:0], s.blockSize)
		if extraChecks && len(s.buf) != s.blockSize {
			panic("unexpected padding length")
		}

		s.done = true // to prevent another read
		return true
	}

	// Otherwise, the error is real
	s.err = err
	return false
}

// Err returns the last error encountered by the splitter, or nil if no error
// occurred.
func (s *splitter) Err() error {
	return s.err
}

// Block returns the current block of bytes from the splitter. The returned
// buffer is only valid until the next call to Next.
func (s *splitter) Block() []byte {
	return s.buf
}

// Reset will reset the splitter to read from the beginning of the given reader.
// This will clear any error state and allow the splitter to be reused.
//
// The block size is not reset by this method.
func (s *splitter) Reset(r io.Reader) {
	s.r = r
	s.err = nil
	s.done = false
}
