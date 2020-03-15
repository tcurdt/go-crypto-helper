package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// go test -v ./crypto -run TestEncryptionAndDecryption
func TestEncryptionAndDecryption(t *testing.T) {

	key := NewEncryptionKey()
	plaintext := []byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	}

	ciphertext, err := Encrypt(plaintext, key)
	assert.Nil(t, err)

	decrypted, err := Decrypt(ciphertext, key)
	assert.Nil(t, err)

	assert.Equal(t, plaintext, decrypted)
}
