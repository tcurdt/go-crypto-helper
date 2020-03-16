package crypto

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// go test -v -run TestEncodeAndDecodeSigningKey
func TestEncodeAndDecodeSigningKey(t *testing.T) {

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Date", time.Now().UTC().Format(time.RFC1123))

	prv, err := NewSigningKeyPrivate()
	require.Nil(t, err)
	pub := &prv.PublicKey

	body := []byte{}
	err = Sign(req, body, prv)
	require.Nil(t, err)

	prvStr, err := SigningKeyPrivateEncode(prv)
	require.Nil(t, err)

	pubStr, err := SigningKeyPublicEncode(pub)
	require.Nil(t, err)

	prv2, err := SigningKeyPrivateDecode(prvStr)
	require.Nil(t, err)

	pub2, err := SigningKeyPublicDecode(pubStr)
	require.Nil(t, err)

	prv2Str, err := SigningKeyPrivateEncode(prv2)
	require.Nil(t, err)

	pub2Str, err := SigningKeyPublicEncode(pub2)
	require.Nil(t, err)

	require.Equal(t, prvStr, prv2Str)
	require.Equal(t, pubStr, pub2Str)

	err = Verify(req, body, pub)
	require.Nil(t, err)

	err = Verify(req, body, pub2)
	require.Nil(t, err)

}
