package crypto

import (
	"crypto/hmac"
	"crypto/sha512"

	"github.com/gtank/cryptopasta"
)

// EncryptionKey ...
type EncryptionKey = [32]byte

// CombineKeys ...
func CombineKeys(hkey *EncryptionKey, keys ...*EncryptionKey) (*EncryptionKey, error) {

	h := hmac.New(sha512.New512_256, hkey[:])
	for _, key := range keys {
		h.Write(key[:])
	}
	r := h.Sum(nil)

	key := &EncryptionKey{}
	for i := 0; i < len(key); i++ {
		key[i] = r[i]
	}
	return key, nil
}

// NewEncryptionKey ...
func NewEncryptionKey() *EncryptionKey {
	return cryptopasta.NewEncryptionKey()
}

// Encrypt ...
func Encrypt(plaintext []byte, key *EncryptionKey) ([]byte, error) {
	return cryptopasta.Encrypt(plaintext, key)
}

// Decrypt ...
func Decrypt(ciphertext []byte, key *EncryptionKey) ([]byte, error) {
	return cryptopasta.Decrypt(ciphertext, key)
}
