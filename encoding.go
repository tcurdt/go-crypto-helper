package crypto

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
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

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}

	return Encode(der), nil
}

// SigningKeyPrivateDecode ...
func SigningKeyPrivateDecode(key string) (*SigningKeyPrivate, error) {

	bytes, err := Decode(key)
	if err != nil {
		return nil, err
	}

	k, err := x509.ParseECPrivateKey(bytes)
	if err != nil {
		return nil, err
	}
	return k, nil
}

// SigningKeyPublicEncode ...
func SigningKeyPublicEncode(key *SigningKeyPublic) (string, error) {

	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}

	return Encode(der), nil
}

// SigningKeyPublicDecode ...
func SigningKeyPublicDecode(key string) (*SigningKeyPublic, error) {

	bytes, err := Decode(key)
	if err != nil {
		return nil, err
	}

	k, err := x509.ParsePKIXPublicKey(bytes)
	if err != nil {
		return nil, err
	}

	pub, ok := k.(*SigningKeyPublic)
	if !ok {
		return nil, errors.New("data was not a public key")
	}

	return pub, nil
}
