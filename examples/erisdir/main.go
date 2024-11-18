package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/andrew-d/eris-go"
)

var zeroSecret [eris.ConvergenceSecretSize]byte

func main() {
	if len(os.Args) < 4 {
		printUsage()
		os.Exit(1)
	}

	dir := os.Args[1]
	cmd := os.Args[2]
	arg := os.Args[3]

	switch cmd {
	case "put":
		if err := putFile(dir, arg); err != nil {
			fmt.Printf("error: %v", err)
			os.Exit(1)
		}
	case "get":
		if err := getFile(dir, arg, os.Stdout); err != nil {
			fmt.Printf("error: %v", err)
			os.Exit(1)
		}
	}
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  erisdir is a basic utility to read and write ERIS-encoded files to a")
	fmt.Println("  store on disk. try one of the following commands:")
	fmt.Println("")
	fmt.Printf("  %s <directory> put <file>\n", os.Args[0])
	fmt.Printf("  %s <directory> get <urn>\n", os.Args[0])
}

func putFile(dir, file string) error {
	// If the dir is not a directory, return an error
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return fmt.Errorf("directory %s does not exist", dir)
	}

	// Open the given file. As a special case, if the file is "-", read from stdin.
	var rdr io.Reader
	if file == "-" {
		rdr = os.Stdin
	} else {
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		defer f.Close()
		rdr = f
	}

	enc := eris.NewEncoder(rdr, zeroSecret, 32*1024)

	var written, skipped int
	for enc.Next() {
		block := enc.Block()
		ref := enc.Reference()

		// Write the block to disk, keyed by the hex-encoded reference.
		path := filepath.Join(dir, hex.EncodeToString(ref[:]))

		// Create the file, but if it already exists, skip it since we
		// know that the content is already there.
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err != nil {
			if os.IsExist(err) {
				skipped++
				continue
			}
			return err
		}

		// Write the block to the file.
		_, err = f.Write(block)
		err2 := f.Close()
		if err := errors.Join(err, err2); err != nil {
			return err
		}

		written++
	}
	if err := enc.Err(); err != nil {
		return fmt.Errorf("encoding error: %w", err)
	}

	fmt.Printf("wrote %d blocks, skipped %d\n", written, skipped)
	fmt.Printf("%s\n", enc.Capability().MustURN())
	return nil
}

func getFile(dir, urn string, w io.Writer) error {
	// If the dir is not a directory, return an error
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return fmt.Errorf("directory %s does not exist", dir)
	}

	// Parse the given URN.
	rc, err := eris.ParseReadCapabilityURN(urn)
	if err != nil {
		return fmt.Errorf("invalid URN %q: %w", urn, err)
	}

	// Our fetch function will look up a file in the given directory by the
	// hex-encoded value of the reference.
	fetch := func(_ context.Context, ref eris.Reference, buf []byte) ([]byte, error) {
		path := filepath.Join(dir, hex.EncodeToString(ref[:]))
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		// Use the provided buffer as scratch space for reading the
		// block; the buffer is guaranteed to be exactly blockSize.
		if _, err := io.ReadFull(f, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}

	// Iteratively decode the file, writing the blocks to the output writer.
	ctx := context.Background()
	dec := eris.NewDecoder(fetch, rc)
	for dec.Next(ctx) {
		if _, err := w.Write(dec.Block()); err != nil {
			return fmt.Errorf("writing block: %w", err)
		}
	}
	if err := dec.Err(); err != nil {
		return fmt.Errorf("decoding error: %w", err)
	}

	return nil
}
