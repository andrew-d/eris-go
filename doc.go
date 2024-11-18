// Package eris implements the Encoding for Robust Immutable Storage (ERIS)
// encoding, version 1.0.0, as described in the spec:
//
//	https://eris.codeberg.page/spec/
//
// ERIS is an encoding of arbitrary content into a set of uniformly sized,
// encrypted and content-addressed blocks as well as a short identifier that
// can be encoded as an URN. The content can be reassembled from the blocks
// only with this identifier. The encoding is defined independent of any
// storage and transport layer or any specific application.
//
// This package does not implement any storage layer, but only concerns itself
// with the encoding and decoding of content. Users of this package are
// expected to implement their own storage layer, which can be as simple as
// files stored on-disk. Example(s) of how to use this package are provided in
// the 'examples' directory.
package eris
