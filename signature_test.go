package crypto

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// go test -v ./crypto -run TestSignAndVerify
func TestSignAndVerify(t *testing.T) {

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Date", time.Now().UTC().Format(time.RFC1123))

	key, err := NewSigningKey()
	assert.Nil(t, err)

	body := []byte{}
	err = Sign(req, body, key)
	assert.Nil(t, err)

	err = Verify(req, body, &key.PublicKey)
	assert.Nil(t, err)

}
