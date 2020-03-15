package crypto

import (
	"encoding/base64"
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
