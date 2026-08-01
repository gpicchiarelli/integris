// Command integris-verify-config validates an Integris configuration document
// and prints its canonical JSON and digest without network, archive mutation,
// key use, or journal write (docs/specifications/configuration.md).
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/gpicchiarelli/integris/internal/config"
)

func main() {
	path := flag.String("config", "", "path to configuration JSON")
	flag.Parse()
	if *path == "" {
		fmt.Fprintln(os.Stderr, "usage: integris-verify-config -config path.json")
		os.Exit(2)
	}
	data, err := os.ReadFile(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integris-verify-config: %v\n", err)
		os.Exit(1)
	}
	doc, err := config.Parse(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integris-verify-config: invalid: %v\n", err)
		os.Exit(1)
	}
	sum := doc.Digest()
	fmt.Printf("digest_sha256=%s\n", hex.EncodeToString(sum[:]))
	fmt.Printf("canonical_json=%s\n", doc.CanonicalJSON())
}
