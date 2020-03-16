package crypto

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// go test -v ./crypto -run TestSignAndVerify
func TestSignAndVerify(t *testing.T) {

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Date", time.Now().UTC().Format(time.RFC1123))

	prv, pub, err := NewSigningPair()
	require.Nil(t, err)

	body := []byte{}
	err = Sign(req, body, prv)
	require.Nil(t, err)

	err = Verify(req, body, pub)
	require.Nil(t, err)

}
