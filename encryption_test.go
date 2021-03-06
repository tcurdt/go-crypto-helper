package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// go test -v -run TestEncryptionAndDecryption
func TestEncryptionAndDecryption(t *testing.T) {

	key := NewEncryptionKey()
	plaintext := []byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	}

	ciphertext, err := Encrypt(plaintext, key)
	require.Nil(t, err)

	decrypted, err := Decrypt(ciphertext, key)
	require.Nil(t, err)

	require.Equal(t, plaintext, decrypted)
}
