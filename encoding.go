package crypto

import (
	"encoding/base64"

	"github.com/gtank/cryptopasta"
)

// Encode ...
func Encode(b []byte) string {
	return base64.URLEncoding.EncodeToString(b)
}

// Decode ...
func Decode(s string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(s)
}

// EncryptionKeyEncode ...
func EncryptionKeyEncode(key *EncryptionKey) string {
	return Encode(key[:])
}

// EncryptionKeyDecode ...
func EncryptionKeyDecode(key string) (*EncryptionKey, error) {

	bin, err := Decode(key)
	if err != nil {
		return nil, err
	}
	ret := &EncryptionKey{}
	for i := 0; i < len(ret); i++ {
		ret[i] = bin[i]
	}
	return ret, nil
}

// SigningKeyPrivateEncode ...
func SigningKeyPrivateEncode(key *SigningKeyPrivate) (string, error) {

	b, err := cryptopasta.EncodePrivateKey(key)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// SigningKeyPrivateDecode ...
func SigningKeyPrivateDecode(key string) (*SigningKeyPrivate, error) {

	k, err := cryptopasta.DecodePrivateKey([]byte(key))
	if err != nil {
		return nil, err
	}

	return k, nil
}

// SigningKeyPublicEncode ...
func SigningKeyPublicEncode(key *SigningKeyPublic) (string, error) {

	b, err := cryptopasta.EncodePublicKey(key)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// SigningKeyPublicDecode ...
func SigningKeyPublicDecode(key string) (*SigningKeyPublic, error) {

	k, err := cryptopasta.DecodePublicKey([]byte(key))
	if err != nil {
		return nil, err
	}

	return k, nil
}
