package eris

// padBlock will add padding to the given block starting at 'start', as per the
// ERIS specification. The specification states that:
//
//	The procedure Pad(input, block-size) given input of length n adds a
//	mandatory byte valued 0x80 (hexadecimal) to input followed by m <
//	block-size bytes valued 0x00 such that n + m + 1 is the smallest
//	multiple of block-size.
//
// This is the same as the padding used in libsodium, which is defined as the
// ISO/IEC 7816-4 padding algorithm.
//
// We pad in-place vs. appending and returning a new slice since benchmarks
// show that it is a little bit fater.
func padBlock(buf []byte, start, blockSize int) {
	n := len(buf)
	if n > blockSize {
		panic("block too large")
	}
	if start < 0 || start > n {
		panic("invalid start")
	}

	// If we're already at the block size, we don't need to pad.
	if start == blockSize {
		return
	}

	// Add the padding start byte to the buffer, then fill the rest with
	// zero.
	buf[start] = 0x80
	for i := start + 1; i < blockSize; i++ {
		buf[i] = 0x00
	}
}

// removePadding will remove the padding from the given block, as per the ERIS
// specification, and return the unpadded slice. The specification states that:
//
//	The procedure Unpad(input, block-size) starts reading bytes from the
//	end of input until a 0x80 is read and then returns bytes of input
//	before the 0x80. The procedure throws an error if a value other than
//	0x00 is read before reading 0x80, if no 0x80 is read after reading
//	block-size bytes from the end of input or if length of input is less
//	than block-size.
//
// This is the same as the padding used in libsodium, which is defined as the
// ISO/IEC 7816-4 padding algorithm.
//
// The returned slice is a sub-slice of the input slice.
func removePadding(buf []byte, blockSize int) ([]byte, error) {
	if len(buf) < blockSize {
		return nil, ErrInvalidPadding
	}

	n := len(buf)
	for i := 0; i < blockSize; i++ {
		// Read the ith byte from the end of input.
		b := buf[n-i-1]

		if b == 0x80 {
			// Special marker is reached, return everything before it.
			return buf[:n-i-1], nil
		} else if b == 0x00 {
			// Continue with next byte from right.
			continue
		} else {
			// Padding must be 0x00 or 0x80; anything else is an
			// error.
			return nil, ErrInvalidPadding
		}
	}

	// No 0x80 has been read after reading block-size bytes from the right
	// of the buffer, so the padding is invalid.
	return nil, ErrInvalidPadding
}
