package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/gtank/cryptopasta"
)

type SigningKeyPrivate = ecdsa.PrivateKey
type SigningKeyPublic = ecdsa.PublicKey

const (
	headerSignature     = "x-signature"
	headerSignedHeaders = "x-signed-headers"
)

// NewSigningKeyPrivate ...
func NewSigningKeyPrivate() (*SigningKeyPrivate, error) {
	return cryptopasta.NewSigningKey()
}

// Sign ...
func Sign(req *http.Request, body []byte, privKey *SigningKeyPrivate) error {

	message, err := Canonize(req, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	signature, err := cryptopasta.Sign(message, privKey)
	if err != nil {
		return err
	}

	encodedSignature := Encode(signature)

	req.Header.Set(headerSignature, encodedSignature)

	return nil
}

// Verify ...
func Verify(req *http.Request, body []byte, pubKey *SigningKeyPublic) error {

	message, err := Canonize(req, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	encodedSignature := req.Header.Get(headerSignature)

	signature, err := Decode(encodedSignature)
	if err != nil {
		return err
	}

	if !cryptopasta.Verify(message, signature, pubKey) {
		return fmt.Errorf("invalid")
	}

	return nil
}

// Canonize ...
func Canonize(req *http.Request, body io.Reader) ([]byte, error) {
	var msg bytes.Buffer

	// Begin writing the target of the signature.
	// start with the request target:
	//     lower(METHOD) <space > PATH <'?'> canonical(QUERY) <newline>
	// where canonical(QUERY) is the query params, lexicographically sorted
	// in ascending order (including param name, = sign, and value),
	// and delimited by an '&'.
	// If no query params are set, the '?' is omitted.
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	msg.WriteString(strings.ToLower(method))
	msg.WriteRune(' ')
	msg.WriteString(req.URL.EscapedPath())

	if len(req.URL.RawQuery) > 0 {
		msg.WriteRune('?')

		parts := strings.Split(req.URL.RawQuery, "&")
		sort.Strings(parts)
		msg.WriteString(strings.Join(parts, "&"))
	}

	msg.WriteRune('\n')

	// Next, add all headers. These are the headers listed in the
	// X-Signed-Headers  header, in the order they are listed, followed by
	// the X-Signed-Headers header itself.
	//
	// Headers are written in the form:
	//     lower(NAME) <colon> <space> VALUES <newline>
	// Values have all optional whitespace removed.
	// If the header occurs multiple times on the request, the values are
	// included delimited by `, `, in the order they appear on the request.
	//
	// The X-Signed-Headers header includes the list of all signed headers,
	// lowercased, and delimited by a space. Only one occurrence of
	// X-Signed-Headers should exist on a request. If more than one exists,
	// The first is used.
	headers := strings.Split(req.Header.Get(headerSignedHeaders), " ")
	headers = append(headers, headerSignedHeaders)
	for _, h := range headers {
		ch := http.CanonicalHeaderKey(h)

		rhvs := req.Header[ch]
		if ch == "Host" {
			host := req.Host
			if host == "" {
				host = req.URL.Host
			}

			rhvs = []string{host}
		}

		msg.WriteString(strings.ToLower(h))
		msg.WriteString(": ")

		var hvs []string
		for _, hv := range rhvs {
			hvs = append(hvs, strings.TrimSpace(hv))
		}
		msg.WriteString(strings.Join(hvs, ", "))
		msg.WriteRune('\n')
	}

	_, err := io.Copy(&msg, body)
	return msg.Bytes(), err
}
