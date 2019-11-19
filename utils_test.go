package oauth1

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestEscape(t *testing.T) {
	testCases := []struct {
		input  string
		output string
	}{
		{
			input:  "=%3D",
			output: "%3D%253D",
		},
		{
			input:  "r b",
			output: "r%20b",
		},
		{
			input:  "9djdj82h48djs9d2",
			output: "9djdj82h48djs9d2",
		},
	}

	for _, c := range testCases {
		actual := escape(c.input)
		if actual != c.output {
			t.Fatalf("\nExpected: %s\nGot:      %s\n", c.output, actual)
		}
	}
}

func TestParseOauthHeader(t *testing.T) {
	exampleHeader := `OAuth realm="Photos",
	oauth_consumer_key="dpf43f3p2l4k3l03",
	oauth_token="nnch734d00sl2jdk",
	oauth_signature_method="HMAC-SHA1",
	oauth_timestamp="137131202",
	oauth_nonce="chapoH",
	oauth_signature="MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D"`

	keyVals := parseOauthHeader(exampleHeader)
	if len(keyVals) != 7 {
		t.Fatalf("Expected 7 items parsed from oauth header. result: %+v", keyVals)
	}
}

func TestParseBody(t *testing.T) {
	body := url.Values{}
	body.Add("a", "a")
	body.Add("b", "b")

	req, _ := http.NewRequest("POST", "http://example.com", strings.NewReader(body.Encode()))
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	res := parseFormBody(req)

	if len(res) != 2 {
		t.Fatalf("Expected 2 items from form body")
	}
}

func TestBaseStrURI(t *testing.T) {
	type baseURIInput struct {
		scheme string
		host   string
		port   string
		path   string
	}
	testCases := []struct {
		input    baseURIInput
		expected string
	}{
		{
			input: baseURIInput{
				scheme: "HTTP",
				host:   "example.com",
				port:   "80",
				path:   "/",
			},
			expected: "http://example.com/",
		},
		{
			input: baseURIInput{
				scheme: "HTTP",
				host:   "example.com",
				port:   "8080",
				path:   "/",
			},
			expected: "http://example.com:8080/",
		},
		{
			input: baseURIInput{
				scheme: "HTTP",
				host:   "example.com",
				port:   "",
				path:   "/r%20v/X?id=123",
			},
			expected: "http://example.com/r%20v/X",
		},
		{
			input: baseURIInput{
				scheme: "HTTP",
				host:   "example.com",
				port:   "8080",
				path:   "/r%20v/X?id=123",
			},
			expected: "http://example.com:8080/r%20v/X",
		},
	}

	for _, c := range testCases {
		output := getBaseStrURI(c.input.scheme, c.input.host, c.input.port, c.input.path)
		if output != c.expected {
			t.Fatalf("\nExpected:\n%s\nGot:\n%s\n", c.expected, output)
		}
	}
}
