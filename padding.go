package eris

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
