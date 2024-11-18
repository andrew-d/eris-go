## eris-go

[![Go Reference](https://pkg.go.dev/badge/github.com/andrew-d/eris-go.svg)](https://pkg.go.dev/github.com/andrew-d/eris-go)

`eris-go` is a package that implements encoding and decoding of the Encoding
for Robust Immutable Storage (ERIS) format.

ERIS is an encoding of arbitrary content into a set of uniformly sized,
encrypted and content-addressed blocks as well as a short identifier that can
be encoded as an URN. The content can be reassembled from the blocks only with
this identifier. The encoding is defined independent of any storage and
transport layer or any specific application.

This package does not implement any storage layer, but only concerns itself
with the encoding and decoding of content. Users of this package are
expected to implement their own storage layer, which can be as simple as
files stored on-disk. Example(s) of how to use this package are provided in
the 'examples' directory.

This package intentionally does not have any dependencies other than Go's
`x/crypto` library for cryptographic primitives.

See [the spec][spec] for more details on the format.

[spec]: https://eris.codeberg.page/spec/
