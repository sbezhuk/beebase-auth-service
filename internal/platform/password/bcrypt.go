// Package password hashes and verifies user passwords with bcrypt.
package password

import "golang.org/x/crypto/bcrypt"

// BcryptHasher implements application/auth.PasswordHasher using bcrypt.
type BcryptHasher struct {
	cost int
}

// NewBcryptHasher returns a BcryptHasher using cost, or bcrypt's default
// cost if cost is not a valid bcrypt cost.
func NewBcryptHasher(cost int) *BcryptHasher {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = bcrypt.DefaultCost
	}
	return &BcryptHasher{cost: cost}
}

// Hash returns the bcrypt hash of plainPassword.
func (h *BcryptHasher) Hash(plainPassword string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(plainPassword), h.cost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

// Verify returns nil if plainPassword matches hash, or an error otherwise.
func (h *BcryptHasher) Verify(hash, plainPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plainPassword))
}
