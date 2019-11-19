package oauth1

import (
	"fmt"
	"regexp"
	"testing"
)

func TestSignatureMethodToString(t *testing.T) {
	testCases := []struct {
		in       SignatureMethod
		expected string
	}{
		{
			in:       Plaintext,
			expected: "PLAINTEXT",
		},
		{
			in:       HmacSha1,
			expected: "HMAC-SHA1",
		},
		{
			in:       RsaSha1,
			expected: "RSA-SHA1",
		},
	}

	for _, c := range testCases {
		res := c.in.ToString()
		if res != c.expected {
			t.Fatalf("expected:\n%s\ngot:\n%s\n", c.expected, res)
		}
	}
}

func TestOauthParamsToParams(t *testing.T) {
	op := oauthParams{
		ConsumerKey:     "foo",
		Token:           "bar",
		SignatureMethod: "PLAINTEXT",
		Timestamp:       "12345",
		Nonce:           "12398uhfe",
		Version:         "1.0",
	}
	params := op.toParams()
	if len(params) != 6 {
		t.Fatalf("not all params converted:\n%+v\n=>\n%+v", op, params)
	}
}

func TestOauthParamsToHeader(t *testing.T) {
	oauthRegexTemplate := `OAuth ((oauth_[a-z_]+=\"[^"]+\")(,?\s*)){%d}`
	params := oauthParams{
		ConsumerKey:     "foo",
		Token:           "bar",
		SignatureMethod: "PLAINTEXT",
		Timestamp:       "12345",
		Nonce:           "12398uhfe",
		Version:         "1.0",
	}

	header := params.toHeader()
	re, _ := regexp.Compile(fmt.Sprintf(oauthRegexTemplate, len(params.toParams())))
	if !re.MatchString(header) {
		t.Fatalf("Header did not match regex:\n%s\n\n%+v", header, *re)
	}
}
