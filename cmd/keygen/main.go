// Command keygen generates a new Ed25519 key pair for JWT_PRIVATE_KEY and
// prints it along with the key ID that will appear in issued tokens and in
// this service's JWKS document.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/sbezhuk/beebase-auth-service/internal/platform/jwtauth"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate key:", err)
		os.Exit(1)
	}

	fmt.Println("JWT_PRIVATE_KEY=" + base64.StdEncoding.EncodeToString(priv))
	fmt.Println("# kid:", jwtauth.KeyID(pub))
}
