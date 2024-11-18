package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/andrew-d/eris-go"
)

var (
	putFlagSet = flag.NewFlagSet("put", flag.ExitOnError)
	secretFlag = putFlagSet.String("secret", "", "convergence secret; empty is the zero secret")

	getFlagSet = flag.NewFlagSet("get", flag.ExitOnError)
	outFlag    = getFlagSet.String("o", "", "output file; empty is stdout")

	secret [eris.ConvergenceSecretSize]byte
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	log.SetOutput(os.Stderr)

	cmd := os.Args[1]
	switch cmd {
	case "put":
		putFlagSet.Parse(os.Args[2:])
		if *secretFlag != "" {
			// Decode as hex.
			dec, err := hex.DecodeString(*secretFlag)
			if err != nil {
				log.Fatalf("invalid secret: %v", err)
			}
			if len(dec) != eris.ConvergenceSecretSize {
				log.Fatalf("invalid secret: expected %d bytes, got %d", eris.ConvergenceSecretSize, len(dec))
			}
			copy(secret[:], dec)
		}

		if putFlagSet.NArg() != 2 {
			log.Printf("expected 2 arguments, got %d", putFlagSet.NArg())
			printUsage()
			os.Exit(1)
		}

		dir := putFlagSet.Arg(0)
		input := putFlagSet.Arg(1)
		if err := putFile(dir, input); err != nil {
			log.Fatalf("error: %v", err)
			os.Exit(1)
		}

	case "get":
		getFlagSet.Parse(os.Args[2:])

		var out io.Writer = os.Stdout
		if *outFlag != "" {
			// Create the output file; if it already exists, don't overwrite it.
			f, err := os.OpenFile(*outFlag, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatalf("error creating output file: %v", err)
			}
			defer f.Close()
			out = f
		}

		if getFlagSet.NArg() != 2 {
			log.Printf("expected 2 arguments, got %d", getFlagSet.NArg())
			printUsage()
			os.Exit(1)
		}

		dir := getFlagSet.Arg(0)
		urn := getFlagSet.Arg(1)
		if err := getFile(dir, urn, out); err != nil {
			log.Fatalf("error: %v", err)
			os.Exit(1)
		}

	case "-h", "-help", "--help", "help":
		printUsage()

	default:
		log.Fatalf("unknown command %q", cmd)
		printUsage()
	}
}

func putFile(dir, file string) error {
	// If the dir is not a directory, return an error
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return fmt.Errorf("directory %s does not exist", dir)
	}

	var (
		rdr       io.Reader
		blockSize int = 32 * 1024
	)
	if file == "-" {
		// As a special case, if the file is "-", read from stdin.
		rdr = os.Stdin
	} else {
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		defer f.Close()

		rdr = f

		// If the file is less than 16KiB in size, then use 1KiB blocks
		// to save on space.
		fi, err := f.Stat()
		if err == nil && fi.Size() < 16*1024 {
			log.Printf("file is smaller than 16KiB, using 1KiB blocks")
			blockSize = 1024
		}
	}

	enc := eris.NewEncoder(rdr, secret, blockSize)

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

	log.Printf("wrote %d blocks, skipped %d", written, skipped)
	fmt.Println(enc.Capability().MustURN())
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

func printUsage() {
	fmt.Println("usage:")
	fmt.Println("  erisdir is a utility to read and write ERIS-encoded files to/from a")
	fmt.Println("  store on disk")
	fmt.Println("")
	fmt.Println("  a store directory contains zero or more files, each of which is a")
	fmt.Println("  single ERIS block. each block is stored in a file with the name being")
	fmt.Println("  the hex-encoded hash of that block's contents")
	fmt.Println("")
	fmt.Println("commands:")
	fmt.Println("  put [flags] <store-dir> <file>")
	fmt.Println("    write the given file to the store directory and print its ERIS URN")
	fmt.Println("")
	fmt.Println("    flags:")
	fmt.Println("      -secret <secret>")
	fmt.Println("        the convergence secret to use when writing the file")
	fmt.Println("")
	fmt.Println("  get [flags] <store-dir> <urn>")
	fmt.Println("    read the file with the given ERIS URN from the store directory")
	fmt.Println("")
	fmt.Println("    flags:")
	fmt.Println("      -o <path>")
	fmt.Println("        write the output to the given file instead of stdout")
}
